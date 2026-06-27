package com.w3auth.backend.infrastructure;

import com.w3auth.backend.verification.ChainClient;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Duration;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.RawTransactionManager;
import org.web3j.tx.gas.DefaultGasProvider;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@link Web3jChainClient} against a real Anvil node.
 *
 * <p>Proves all four parse outcomes through the real adapter: EOA → no code,
 * deployed address → has code, magic-return fixture → true, reject fixture → false.
 *
 * <p>Fixture bytecodes are hand-assembled (no Solidity toolchain in the build):
 *
 * <pre>
 * ALWAYS_VALID runtime (41 bytes):
 *   PUSH32 0x1626ba7e0000...00  ; ABI-encoded bytes4 magic value
 *   PUSH1 0x00                   ; memory offset
 *   MSTORE                       ; mem[0..31] = magic value
 *   PUSH1 0x20                   ; return length = 32
 *   PUSH1 0x00                   ; return offset = 0
 *   RETURN                       ; → 0x1626ba7e0000...00
 *
 * NEVER_VALID runtime: identical except PUSH32 value is 0xdeadbeef0000...00
 *
 * Constructor (12 bytes, same for both):
 *   PUSH1 0x29 PUSH1 0x0c PUSH1 0x00 CODECOPY  ; copy 41-byte runtime to mem[0]
 *   PUSH1 0x29 PUSH1 0x00 RETURN                ; deploy it
 * </pre>
 */
@Testcontainers
class Web3jChainClientIntegrationTest {

    // Anvil dev account #0 — deterministic key, pre-funded on every anvil instance
    private static final String DEV_PRIVATE_KEY =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    // Anvil dev account #1 — used as a bare EOA (no deployed code)
    private static final String DEV_ACCOUNT_1 =
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    // Anvil dev account #1 private key — used to forge signatures in deployless tests
    private static final String DEV_PRIVATE_KEY_1 =
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    private static final long ANVIL_CHAIN_ID = 31337L;

    // Expected runtime bytecode (41 bytes each) — the portion CODECOPY deploys.
    // getCode on a deployed fixture must return exactly this string.
    // Format: 7f <32 bytes for PUSH32> 60 00 52 60 20 60 00 f3
    //         └── PUSH32 ──────────────┘ PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN
    private static final String EXPECTED_MAGIC_RUNTIME =
            "0x7f1626ba7e0000000000000000000000000000000000000000000000000000000060005260206000f3";
    private static final String EXPECTED_REJECT_RUNTIME =
            "0x7fdeadbeef0000000000000000000000000000000000000000000000000000000060005260206000f3";

    // Constructor (12 bytes): PUSH1 0x29; PUSH1 0x0c; PUSH1 0x00; CODECOPY;
    //                          PUSH1 0x29; PUSH1 0x00; RETURN
    // Runtime (41 bytes = 0x29): PUSH32 <value>; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN
    // PUSH32 (7f) consumes exactly 32 bytes. The 4-byte magic/value is followed by
    // 28 zero bytes to fill the 32-byte slot: 4 + 28 = 32. Then PUSH1 0 + MSTORE +
    // PUSH1 32 + PUSH1 0 + RETURN returns the 32-byte word from mem[0].
    private static final String ALWAYS_VALID_CREATION =
            "6029600c60003960296000f3"                                       // constructor
            + "7f1626ba7e"                                                  // PUSH32 + first 4 bytes of magic
            + "00000000000000000000000000000000000000000000000000000000"    // remaining 28 zero bytes
            + "60005260206000f3";                                            // PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN

    private static final String NEVER_VALID_CREATION =
            "6029600c60003960296000f3"                                       // constructor (identical)
            + "7fdeadbeef"                                                  // PUSH32 + 0xdeadbeef
            + "00000000000000000000000000000000000000000000000000000000"    // remaining 28 zero bytes
            + "60005260206000f3";                                            // PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN

    @Container
    static final GenericContainer<?> ANVIL = new GenericContainer<>(
            DockerImageName.parse("ghcr.io/foundry-rs/foundry:v1.1.0"))
            .withExposedPorts(8545)
            .withCommand("anvil")
            // In foundry v1.1.0 the anvil binary silently ignores all CLI flags; the
            // bind address must be set via the ANVIL_IP_ADDR environment variable.
            // Without it, anvil defaults to 127.0.0.1, which is unreachable via Docker
            // port-mapping (Docker maps to the container's external IP, not its loopback).
            .withEnv("ANVIL_IP_ADDR", "0.0.0.0")
            // Wait for the log line that proves anvil bound to 0.0.0.0 (not 127.0.0.1).
            .waitingFor(Wait.forLogMessage(".*Listening on 0\\.0\\.0\\.0.*", 1)
                    .withStartupTimeout(Duration.ofSeconds(60)));

    private static Web3j web3j;
    private static ChainClient chainClient;
    private static String alwaysValidAddress;
    private static String neverValidAddress;

    @BeforeAll
    static void deployFixtures() throws Exception {
        String rpcUrl = "http://" + ANVIL.getHost() + ":" + ANVIL.getMappedPort(8545);
        web3j = Web3j.build(new HttpService(rpcUrl));

        // Anvil logs "Listening on" before its HTTP layer fully initialises. OkHttp
        // (used by web3j) pools connections and will reuse a dead connection from the
        // first failed attempt on every subsequent retry. Use HttpURLConnection (no
        // pooling) so each probe is a guaranteed-fresh TCP connection, and retry for
        // up to 20 s (40 × 500 ms).
        byte[] probeBody = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}"
                .getBytes();
        for (int attempt = 0; ; attempt++) {
            HttpURLConnection conn = null;
            try {
                conn = (HttpURLConnection) new URL(rpcUrl).openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Content-Length", String.valueOf(probeBody.length));
                conn.setDoOutput(true);
                conn.setConnectTimeout(1000);
                conn.setReadTimeout(2000);
                conn.getOutputStream().write(probeBody);
                if (conn.getResponseCode() == 200) break;
            } catch (Exception e) {
                if (attempt >= 40) throw new IllegalStateException(
                        "Anvil HTTP layer not ready after 20 s. Container logs:\n" + ANVIL.getLogs(), e);
                Thread.sleep(500);
            } finally {
                if (conn != null) conn.disconnect();
            }
        }

        chainClient = new Web3jChainClient(web3j);

        Credentials credentials = Credentials.create(DEV_PRIVATE_KEY);
        RawTransactionManager txManager =
                new RawTransactionManager(web3j, credentials, ANVIL_CHAIN_ID);

        alwaysValidAddress = deploy(txManager, web3j, ALWAYS_VALID_CREATION);
        neverValidAddress  = deploy(txManager, web3j, NEVER_VALID_CREATION);
    }

    private static String deploy(RawTransactionManager txManager, Web3j web3j,
                                  String creationHex) throws Exception {
        var txResp = txManager.sendTransaction(
                DefaultGasProvider.GAS_PRICE,
                DefaultGasProvider.GAS_LIMIT,
                null,               // to = null → contract creation
                "0x" + creationHex,
                BigInteger.ZERO);

        String txHash = txResp.getTransactionHash();
        // Anvil mines each tx instantly; poll briefly until receipt appears.
        for (int i = 0; i < 20; i++) {
            var receipt = web3j.ethGetTransactionReceipt(txHash).send();
            if (receipt.getTransactionReceipt().isPresent()) {
                return receipt.getTransactionReceipt().get().getContractAddress();
            }
            Thread.sleep(250);
        }
        throw new IllegalStateException("contract not mined within 5 s, txHash=" + txHash);
    }

    // ── four parse outcomes ───────────────────────────────────────────────────

    @Test
    void getCode_onEOA_returnsEmpty() {
        String code = chainClient.getCode(DEV_ACCOUNT_1);
        // eth_getCode on an EOA returns "0x" (no deployed bytecode)
        assertThat(code).satisfiesAnyOf(
                c -> assertThat(c).isEqualTo("0x"),
                c -> assertThat(c).isEmpty());
    }

    @Test
    void getCode_onDeployedContract_returnsNonEmpty() {
        String code = chainClient.getCode(alwaysValidAddress);
        assertThat(code).isNotBlank().isNotEqualTo("0x");
    }

    @Test
    void isValidErc1271Signature_magicFixture_returnsTrue() {
        boolean result = chainClient.isValidErc1271Signature(
                alwaysValidAddress, new byte[32], new byte[0]);
        assertThat(result).isTrue();
    }

    @Test
    void isValidErc1271Signature_rejectFixture_returnsFalse() {
        // "Node said no" (non-magic return) must parse to false, not throw
        boolean result = chainClient.isValidErc1271Signature(
                neverValidAddress, new byte[32], new byte[0]);
        assertThat(result).isFalse();
    }

    // ── bytecode self-verification ────────────────────────────────────────────

    @Test
    void deployedBytecode_matchesExpectedRuntime() {
        // Proves the hand-assembled creation bytecode deployed exactly the
        // intended runtime — not whatever the assembly happened to produce.
        assertThat(chainClient.getCode(alwaysValidAddress))
                .isEqualToIgnoringCase(EXPECTED_MAGIC_RUNTIME);
        assertThat(chainClient.getCode(neverValidAddress))
                .isEqualToIgnoringCase(EXPECTED_REJECT_RUNTIME);
    }

    @Test
    void rawEthCall_magicFixture_returnsExactMagicWord() throws Exception {
        // Bypass the ChainClient adapter — verify raw on-chain behavior of the
        // fixture. These are constant-return stubs (no selector dispatch),
        // so any calldata (including empty) triggers the same PUSH32/MSTORE/RETURN.
        var tx = Transaction.createEthCallTransaction(null, alwaysValidAddress, "0x");
        var response = web3j.ethCall(tx, DefaultBlockParameterName.LATEST).send();
        assertThat(response.hasError()).isFalse();
        assertThat(response.getValue())
                .isEqualToIgnoringCase(
                        "0x1626ba7e00000000000000000000000000000000000000000000000000000000");
    }

    // TODO(commit 2): counterfactual wrapped-sig test via Artifact B (CREATE2 factory fixture)

    @Test
    void deployless_validEoaSignature_returnsTrue() {
        byte[] message = "hello deployless".getBytes(StandardCharsets.UTF_8);
        byte[] hash = Sign.getEthereumMessageHash(message);
        ECKeyPair keyPair = Credentials.create(DEV_PRIVATE_KEY).getEcKeyPair();
        Sign.SignatureData sigData = Sign.signPrefixedMessage(message, keyPair);
        byte[] sig = toEthSig(sigData);
        String signer = Credentials.create(DEV_PRIVATE_KEY).getAddress().toLowerCase();
        assertThat(chainClient.isValidSignatureDeployless(signer, hash, sig)).isTrue();
    }

    @Test
    void deployless_forgedSignature_returnsFalse() {
        byte[] message = "hello deployless".getBytes(StandardCharsets.UTF_8);
        byte[] hash = Sign.getEthereumMessageHash(message);
        // Sign with a different key but claim signer is account #0 — validator must reject.
        ECKeyPair wrongKey = Credentials.create(DEV_PRIVATE_KEY_1).getEcKeyPair();
        Sign.SignatureData sigData = Sign.signPrefixedMessage(message, wrongKey);
        byte[] sig = toEthSig(sigData);
        String signer = Credentials.create(DEV_PRIVATE_KEY).getAddress().toLowerCase();
        assertThat(chainClient.isValidSignatureDeployless(signer, hash, sig)).isFalse();
    }

    @Test
    void deployless_tamperedHash_returnsFalse() {
        byte[] message = "hello deployless".getBytes(StandardCharsets.UTF_8);
        byte[] hash = Sign.getEthereumMessageHash(message);
        ECKeyPair keyPair = Credentials.create(DEV_PRIVATE_KEY).getEcKeyPair();
        Sign.SignatureData sigData = Sign.signPrefixedMessage(message, keyPair);
        byte[] sig = toEthSig(sigData);
        String signer = Credentials.create(DEV_PRIVATE_KEY).getAddress().toLowerCase();
        // Sig is valid for `hash` but not for `tamperedHash`; validator must return 0x00.
        byte[] tamperedHash = hash.clone();
        tamperedHash[0] ^= (byte) 0xFF;
        assertThat(chainClient.isValidSignatureDeployless(signer, tamperedHash, sig)).isFalse();
    }

    @Test
    void rawEthCall_rejectFixture_returnsNonMagicWord() throws Exception {
        var tx = Transaction.createEthCallTransaction(null, neverValidAddress, "0x");
        var response = web3j.ethCall(tx, DefaultBlockParameterName.LATEST).send();
        assertThat(response.hasError()).isFalse();
        String value = response.getValue();
        assertThat(value)
                .isEqualToIgnoringCase(
                        "0xdeadbeef00000000000000000000000000000000000000000000000000000000");
        assertThat(value.toLowerCase())
                .doesNotStartWith("0x1626ba7e");
    }

    private static byte[] toEthSig(Sign.SignatureData sigData) {
        byte[] sig = new byte[65];
        System.arraycopy(sigData.getR(), 0, sig, 0, 32);
        System.arraycopy(sigData.getS(), 0, sig, 32, 32);
        sig[64] = sigData.getV()[0];
        return sig;
    }
}
