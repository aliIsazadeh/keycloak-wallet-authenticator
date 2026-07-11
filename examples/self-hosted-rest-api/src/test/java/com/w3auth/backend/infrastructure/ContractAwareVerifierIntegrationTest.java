package com.w3auth.backend.infrastructure;

import com.w3auth.backend.verification.ContractAwareSignatureVerifier;
import com.w3auth.backend.verification.EthereumSignatureVerifier;
import com.w3auth.backend.verification.SiweMessage;
import com.w3auth.backend.verification.SiweMessageParser;
import com.w3auth.backend.verification.VerificationException;
import com.w3auth.backend.verification.VerificationRequest;
import com.w3auth.backend.verification.VerifiedIdentity;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.RawTransactionManager;
import org.web3j.tx.gas.DefaultGasProvider;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Real ERC-1271 end-to-end proof for M3a.
 *
 * <p>Deploys a compiler-produced {@code OwnerValidator} contract (solc 0.8.34) on a live
 * Anvil node, then exercises the full {@link ContractAwareSignatureVerifier} dispatcher —
 * from HTTP calldata on the EVM back to a {@link VerifiedIdentity}. No mocks.
 *
 * <p>{@code OwnerValidator} implements {@code isValidSignature(bytes32,bytes)} (EIP-1271):
 * it recovers the signer via ecrecover and returns {@code 0x1626ba7e} only if the recovered
 * address equals the constructor-set owner; otherwise it returns {@code 0xffffffff}.
 *
 * <p><b>Hash discipline</b>: the dispatcher computes
 * {@code hash = Sign.getEthereumMessageHash(rawMessage.getBytes(UTF-8))} and passes that to
 * {@code isValidSignature}. The test signs with
 * {@code Sign.signPrefixedMessage(rawMessage.getBytes(UTF-8), keyPair)}, which internally
 * calls {@code getEthereumMessageHash} before the ECDSA step — producing the same 32-byte
 * digest. The on-chain {@code ecrecover} therefore sees the exact hash the test signed over.
 */
@Testcontainers
class ContractAwareVerifierIntegrationTest {

    // Anvil dev account #0 — constructor-set owner of the deployed OwnerValidator.
    private static final String OWNER_PRIVATE_KEY =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    private static final String OWNER_ADDRESS =
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

    // Anvil dev account #1 — the forger; not the owner. Deterministic Anvil key.
    private static final String FORGER_PRIVATE_KEY =
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

    private static final long ANVIL_CHAIN_ID = 31337L;

    /**
     * Compiler-produced creation bytecode for OwnerValidator (solc 0.8.34, optimizer off).
     * The constructor takes one address argument (ABI-encoded as a 32-byte left-padded word)
     * which is appended to this string at deploy time. Embedded exactly as produced by the
     * compiler — do not modify.
     */
    // @formatter:off
    private static final String CREATION_BYTECODE =
        "60a060405234801561000f575f5ffd5b506040516105b73803806105b7833981810160405281019061003191906100c9565b8073ffffffffffffffffffffffffffffffffffffffff1660808173ffffffffffffffffffffffffffffffffffffffff1681525050506100f4565b5f5ffd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6100988261006f565b9050919050565b6100a88161008e565b81146100b2575f5ffd5b50565b5f815190506100c38161009f565b92915050565b5f602082840312156100de576100dd61006b565b5b5f6100eb848285016100b5565b91505092915050565b6080516104a46101135f395f818161015c01526101da01526104a45ff3fe608060405234801561000f575f5ffd5b5060043610610034575f3560e01c80631626ba7e146100385780638da5cb5b14610068575b5f5ffd5b610052600480360381019061004d9190610298565b610086565b60405161005f919061032f565b60405180910390f35b6100706101d8565b60405161007d9190610387565b60405180910390f35b5f604183839050146100a15763ffffffff60e01b90506101d1565b5f5f5f853592506020860135915060408601355f1a9050601b8160ff1610156100d457601b816100d191906103d9565b90505b5f6001888386866040515f81526020016040526040516100f7949392919061042b565b6020604051602081039080840390855afa158015610117573d5f5f3e3d5ffd5b5050506020604051035190505f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16141580156101aa57507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16145b156101c257631626ba7e60e01b9450505050506101d1565b63ffffffff60e01b9450505050505b9392505050565b7f000000000000000000000000000000000000000000000000000000000000000081565b5f5ffd5b5f5ffd5b5f819050919050565b61021681610204565b8114610220575f5ffd5b50565b5f813590506102318161020d565b92915050565b5f5ffd5b5f5ffd5b5f5ffd5b5f5f83601f84011261025857610257610237565b5b8235905067ffffffffffffffff8111156102755761027461023b565b5b6020830191508360018202830111156102915761029061023f565b5b9250929050565b5f5f5f604084860312156102af576102ae6101fc565b5b5f6102bc86828701610223565b935050602084013567ffffffffffffffff8111156102dd576102dc610200565b5b6102e986828701610243565b92509250509250925092565b5f7fffffffff0000000000000000000000000000000000000000000000000000000082169050919050565b610329816102f5565b82525050565b5f6020820190506103425f830184610320565b92915050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f61037182610348565b9050919050565b61038181610367565b82525050565b5f60208201905061039a5f830184610378565b92915050565b5f60ff82169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6103e3826103a0565b91506103ee836103a0565b9250828201905060ff811115610407576104066103ac565b5b92915050565b61041681610204565b82525050565b610425816103a0565b82525050565b5f60808201905061043e5f83018761040d565b61044b602083018661041c565b610458604083018561040d565b610465606083018461040d565b9594505050505056fea26469706673582212202ad75895786a3cc2ee90c65a2a18ae13e48ecad5fa7481aa23988c5da3c879b464736f6c63430008220033";
    // @formatter:on

    @Container
    static final GenericContainer<?> ANVIL = new GenericContainer<>(
            DockerImageName.parse("ghcr.io/foundry-rs/foundry:v1.1.0"))
            .withExposedPorts(8545)
            .withCommand("anvil")
            // CLI flags are silently ignored in v1.1.0; bind address must be set via env var.
            .withEnv("ANVIL_IP_ADDR", "0.0.0.0")
            .waitingFor(Wait.forLogMessage(".*Listening on 0\\.0\\.0\\.0.*", 1)
                    .withStartupTimeout(Duration.ofSeconds(60)));

    private static ContractAwareSignatureVerifier dispatcher;
    private static String contractAddress;

    @BeforeAll
    static void deployContract() throws Exception {
        String rpcUrl = "http://" + ANVIL.getHost() + ":" + ANVIL.getMappedPort(8545);
        Web3j web3j = Web3j.build(new HttpService(rpcUrl));

        // OkHttp (used by web3j) pools connections — reuses a dead connection on retry.
        // Use HttpURLConnection (no pooling) so each probe is a fresh TCP connection.
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

        // ABI-encode owner address: 12 zero bytes (left-pad to 32 bytes) + 20-byte address.
        String ownerHex = OWNER_ADDRESS.startsWith("0x")
                ? OWNER_ADDRESS.substring(2).toLowerCase()
                : OWNER_ADDRESS.toLowerCase();
        String constructorArg = "000000000000000000000000" + ownerHex;
        String creationData = "0x" + CREATION_BYTECODE + constructorArg;

        Credentials ownerCredentials = Credentials.create(OWNER_PRIVATE_KEY);
        RawTransactionManager txManager =
                new RawTransactionManager(web3j, ownerCredentials, ANVIL_CHAIN_ID);

        var txResp = txManager.sendTransaction(
                DefaultGasProvider.GAS_PRICE,
                DefaultGasProvider.GAS_LIMIT,
                null,           // to = null → contract creation
                creationData,
                BigInteger.ZERO);

        String txHash = txResp.getTransactionHash();
        for (int i = 0; i < 20; i++) {
            var receipt = web3j.ethGetTransactionReceipt(txHash).send();
            if (receipt.getTransactionReceipt().isPresent()) {
                contractAddress = receipt.getTransactionReceipt().get().getContractAddress();
                break;
            }
            Thread.sleep(250);
        }
        if (contractAddress == null) {
            throw new IllegalStateException(
                    "OwnerValidator not mined within 5 s, txHash=" + txHash);
        }

        Web3jChainClient chainClient = new Web3jChainClient(web3j);

        // Sanity: non-empty code confirms the deploy landed. No runtime-bytecode constant —
        // the behavioral tests are the proof; the compiler is trusted for this fixture.
        String code = chainClient.getCode(contractAddress);
        assertThat(code).isNotBlank().isNotEqualTo("0x");

        dispatcher = new ContractAwareSignatureVerifier(
                new EthereumSignatureVerifier(), chainClient);
    }

    /**
     * Builds a minimal valid SIWE plaintext whose {@code address} line is the deployed
     * contract address.
     *
     * <p>The dispatcher uses only {@code message.address()} and {@code rawMessage} on the
     * ERC-1271 path — no policy checks (domain, nonce expiry, chainId) are performed by
     * {@link ContractAwareSignatureVerifier} itself. A parseable SIWE string is sufficient.
     */
    private static String buildRawMessage(String address) {
        return "localhost wants you to sign in with your Ethereum account:\n"
                + address + "\n"
                + "\n"
                + "\n"
                + "URI: http://localhost:8080\n"
                + "Version: 1\n"
                + "Chain ID: 31337\n"
                + "Nonce: testnonc1\n"
                + "Issued At: 2026-06-26T00:00:00Z\n"
                + "Expiration Time: 2099-12-31T23:59:59Z";
    }

    /**
     * Signs {@code rawMessage} with {@code keyPair} using the EIP-191 personal-sign scheme.
     * Returns a 65-byte hex signature: r (bytes 0–31) | s (bytes 32–63) | v (byte 64).
     *
     * <p>{@code Sign.signPrefixedMessage} applies {@code getEthereumMessageHash} internally
     * (EIP-191 "Ethereum Signed Message:\n{len}" prefix + Keccak-256) before the ECDSA
     * step, producing the same 32-byte digest the dispatcher passes to {@code isValidSignature}.
     * The on-chain {@code ecrecover} therefore sees exactly the hash the test signed over.
     */
    private static String sign(String rawMessage, ECKeyPair keyPair) {
        Sign.SignatureData sig =
                Sign.signPrefixedMessage(rawMessage.getBytes(StandardCharsets.UTF_8), keyPair);
        byte[] out = new byte[65];
        byte[] r = sig.getR();
        byte[] s = sig.getS();
        System.arraycopy(r, 0, out, 0, Math.min(r.length, 32));
        System.arraycopy(s, 0, out, 32, Math.min(s.length, 32));
        out[64] = sig.getV()[0];
        return "0x" + Numeric.toHexStringNoPrefix(out);
    }

    @Test
    void contractWallet_validSignature_accepted() throws VerificationException {
        String rawMessage = buildRawMessage(contractAddress);
        SiweMessage parsed = SiweMessageParser.parse(rawMessage);
        ECKeyPair ownerKey = ECKeyPair.create(Numeric.hexStringToByteArray(OWNER_PRIVATE_KEY));
        String sig = sign(rawMessage, ownerKey);

        VerifiedIdentity identity = dispatcher.verify(
                new VerificationRequest(parsed, rawMessage, sig));

        // Proves: getCode → non-empty → ERC-1271 path; contract ecrecover recovers the
        // owner → isValidSignature returns 0x1626ba7e → dispatcher returns contract address.
        assertThat(identity.signerAddress()).isEqualToIgnoringCase(contractAddress);
    }

    @Test
    void contractWallet_forgedSignature_rejected() {
        String rawMessage = buildRawMessage(contractAddress);
        SiweMessage parsed = SiweMessageParser.parse(rawMessage);
        // Account #1 signs the same message — they are NOT the owner.
        ECKeyPair forgerKey = ECKeyPair.create(Numeric.hexStringToByteArray(FORGER_PRIVATE_KEY));
        String sig = sign(rawMessage, forgerKey);

        // Proves: ecrecover recovers account #1 (≠ owner) → isValidSignature returns
        // 0xffffffff → dispatcher throws. A fixture that always accepted would fail here.
        assertThatThrownBy(() -> dispatcher.verify(
                new VerificationRequest(parsed, rawMessage, sig)))
                .isInstanceOf(VerificationException.class);
    }

    @Test
    void contractWallet_tamperedSignature_rejected() {
        String rawMessage = buildRawMessage(contractAddress);
        SiweMessage parsed = SiweMessageParser.parse(rawMessage);
        ECKeyPair ownerKey = ECKeyPair.create(Numeric.hexStringToByteArray(OWNER_PRIVATE_KEY));
        // Start from a valid owner signature; flip one bit of r.
        byte[] sigBytes = Numeric.hexStringToByteArray(
                sign(rawMessage, ownerKey).substring(2));
        sigBytes[1] ^= 0x01;
        String tamperedSig = "0x" + Numeric.toHexStringNoPrefix(sigBytes);

        // Proves: tampered sig → ecrecover returns wrong/zero address → 0xffffffff → throws.
        assertThatThrownBy(() -> dispatcher.verify(
                new VerificationRequest(parsed, rawMessage, tamperedSig)))
                .isInstanceOf(VerificationException.class);
    }
}
