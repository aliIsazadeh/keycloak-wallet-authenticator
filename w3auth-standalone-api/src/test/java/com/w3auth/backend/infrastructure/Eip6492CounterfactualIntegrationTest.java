package com.w3auth.backend.infrastructure;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.DynamicBytes;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
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
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * EIP-6492 counterfactual wallet integration test for M3b.
 *
 * <p>Proves the COUNTERFACTUAL branch of the deployless adapter: a contract wallet that has
 * NO code on chain yet. The EIP-6492-wrapped signature causes the universal validator to deploy
 * it (via a CREATE2 factory) and then call EIP-1271 — all inside one deployless eth_call, with
 * no state persisted to the chain.
 *
 * <p>Setup deploys only the Create2Factory. The OwnerValidator wallet address is derived in code
 * via the CREATE2 formula; it is never actually deployed.
 *
 * <p><b>Artifact provenance</b>:
 * <ul>
 *   <li>{@code OWNER_VALIDATOR_CREATION_BYTECODE} — reused verbatim from
 *       {@link ContractAwareVerifierIntegrationTest}.</li>
 *   <li>{@code CREATE2FACTORY_BYTECODE} — supplied as a verified external constant,
 *       solc 0.8.28 --optimize, 924 hex chars. Not regenerated.</li>
 * </ul>
 */
@Testcontainers
class Eip6492CounterfactualIntegrationTest {

    // Anvil dev account #0 — constructor-set owner of the OwnerValidator.
    private static final String OWNER_PRIVATE_KEY =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    private static final String OWNER_ADDRESS =
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

    // Anvil dev account #1 — the forger; not the owner.
    private static final String FORGER_PRIVATE_KEY =
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

    private static final long ANVIL_CHAIN_ID = 31337L;

    // Create2Factory creation bytecode — supplied verbatim, solc 0.8.28 --optimize, 924 hex chars.
    // Do not regenerate or reformat.
    // @formatter:off
    private static final String CREATE2FACTORY_BYTECODE =
            "6080604052348015600e575f5ffd5b506101b28061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610029575f3560e01c80634af63f021461002d575b5f5ffd5b61004061003b3660046100c7565b61005c565b6040516001600160a01b03909116815260200160405180910390f35b5f818351602085015ff5905080610071575f5ffd5b6040516001600160a01b03821681527ff40fcec21964ffb566044d083b4073f29f7f7929110ea19e1b3ebe375d89055e9060200160405180910390a192915050565b634e487b7160e01b5f52604160045260245ffd5b5f5f604083850312156100d8575f5ffd5b823567ffffffffffffffff8111156100ee575f5ffd5b8301601f810185136100fe575f5ffd5b803567ffffffffffffffff811115610118576101186100b3565b604051601f8201601f19908116603f0116810167ffffffffffffffff81118282101715610147576101476100b3565b60405281815282820160200187101561015e575f5ffd5b816020840160208301375f602092820183015296940135945050505056fea264697066735822122012975598524423e4ff014a5c3927d44088f9de856f21286375c02c1baaadef3764736f6c634300081c0033";
    // @formatter:on

    // OwnerValidator creation bytecode — reused verbatim from ContractAwareVerifierIntegrationTest.
    // @formatter:off
    private static final String OWNER_VALIDATOR_CREATION_BYTECODE =
            "60a060405234801561000f575f5ffd5b506040516105b73803806105b7833981810160405281019061003191906100c9565b8073ffffffffffffffffffffffffffffffffffffffff1660808173ffffffffffffffffffffffffffffffffffffffff1681525050506100f4565b5f5ffd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6100988261006f565b9050919050565b6100a88161008e565b81146100b2575f5ffd5b50565b5f815190506100c38161009f565b92915050565b5f602082840312156100de576100dd61006b565b5b5f6100eb848285016100b5565b91505092915050565b6080516104a46101135f395f818161015c01526101da01526104a45ff3fe608060405234801561000f575f5ffd5b5060043610610034575f3560e01c80631626ba7e146100385780638da5cb5b14610068575b5f5ffd5b610052600480360381019061004d9190610298565b610086565b60405161005f919061032f565b60405180910390f35b6100706101d8565b60405161007d9190610387565b60405180910390f35b5f604183839050146100a15763ffffffff60e01b90506101d1565b5f5f5f853592506020860135915060408601355f1a9050601b8160ff1610156100d457601b816100d191906103d9565b90505b5f6001888386866040515f81526020016040526040516100f7949392919061042b565b6020604051602081039080840390855afa158015610117573d5f5f3e3d5ffd5b5050506020604051035190505f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16141580156101aa57507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16145b156101c257631626ba7e60e01b9450505050506101d1565b63ffffffff60e01b9450505050505b9392505050565b7f000000000000000000000000000000000000000000000000000000000000000081565b5f5ffd5b5f5ffd5b5f819050919050565b61021681610204565b8114610220575f5ffd5b50565b5f813590506102318161020d565b92915050565b5f5ffd5b5f5ffd5b5f5ffd5b5f5f83601f84011261025857610257610237565b5b8235905067ffffffffffffffff8111156102755761027461023b565b5b6020830191508360018202830111156102915761029061023f565b5b9250929050565b5f5f5f604084860312156102af576102ae6101fc565b5b5f6102bc86828701610223565b935050602084013567ffffffffffffffff8111156102dd576102dc610200565b5b6102e986828701610243565b92509250509250925092565b5f7fffffffff0000000000000000000000000000000000000000000000000000000082169050919050565b610329816102f5565b82525050565b5f6020820190506103425f830184610320565b92915050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f61037182610348565b9050919050565b61038181610367565b82525050565b5f60208201905061039a5f830184610378565b92915050565b5f60ff82169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6103e3826103a0565b91506103ee836103a0565b9250828201905060ff811115610407576104066103ac565b5b92915050565b61041681610204565b82525050565b610425816103a0565b82525050565b5f60808201905061043e5f83018761040d565b61044b602083018661041c565b610458604083018561040d565b610465606083018461040d565b9594505050505056fea26469706673582212202ad75895786a3cc2ee90c65a2a18ae13e48ecad5fa7481aa23988c5da3c879b464736f6c63430008220033";
    // @formatter:on

    // EIP-6492 magic suffix: 32 bytes (0x6492...6492 pattern).
    private static final byte[] EIP6492_MAGIC_SUFFIX = Numeric.hexStringToByteArray(
            "6492649264926492649264926492649264926492649264926492649264926492");

    // All-zero bytes32 salt — used byte-identically in address derivation and factoryCalldata.
    private static final byte[] SALT = new byte[32];

    @Container
    static final GenericContainer<?> ANVIL = new GenericContainer<>(
            DockerImageName.parse("ghcr.io/foundry-rs/foundry:v1.1.0"))
            .withExposedPorts(8545)
            .withCommand("anvil")
            // CLI flags are silently ignored in v1.1.0; bind address must be set via env var.
            .withEnv("ANVIL_IP_ADDR", "0.0.0.0")
            .waitingFor(Wait.forLogMessage(".*Listening on 0\\.0\\.0\\.0.*", 1)
                    .withStartupTimeout(Duration.ofSeconds(60)));

    private static Web3jChainClient chainClient;
    private static String factoryAddress;
    private static String derivedWalletAddress;
    private static String rawMessage;
    private static byte[] messageHash;
    private static String factoryCalldata;
    private static byte[] walletInitCodeBytes;

    @BeforeAll
    static void setUp() throws Exception {
        String rpcUrl = "http://" + ANVIL.getHost() + ":" + ANVIL.getMappedPort(8545);
        Web3j web3j = Web3j.build(new HttpService(rpcUrl));

        // OkHttp (used by web3j) pools connections — use HttpURLConnection so each probe is fresh.
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

        Credentials ownerCredentials = Credentials.create(OWNER_PRIVATE_KEY);
        RawTransactionManager txManager =
                new RawTransactionManager(web3j, ownerCredentials, ANVIL_CHAIN_ID);

        // Step 1: Deploy only the Create2Factory. The wallet is intentionally NOT deployed.
        var factoryTxResp = txManager.sendTransaction(
                DefaultGasProvider.GAS_PRICE,
                DefaultGasProvider.GAS_LIMIT,
                null,
                "0x" + CREATE2FACTORY_BYTECODE,
                BigInteger.ZERO);

        String factoryTxHash = factoryTxResp.getTransactionHash();
        for (int i = 0; i < 20; i++) {
            var receipt = web3j.ethGetTransactionReceipt(factoryTxHash).send();
            if (receipt.getTransactionReceipt().isPresent()) {
                factoryAddress = receipt.getTransactionReceipt().get().getContractAddress();
                break;
            }
            Thread.sleep(250);
        }
        if (factoryAddress == null) {
            throw new IllegalStateException(
                    "Create2Factory not mined within 5 s, txHash=" + factoryTxHash);
        }

        // Step 2: walletInitCode = OwnerValidator CREATION_BYTECODE ++ (12 zero bytes ++ owner address).
        String ownerHex = OWNER_ADDRESS.startsWith("0x")
                ? OWNER_ADDRESS.substring(2).toLowerCase()
                : OWNER_ADDRESS.toLowerCase();
        String walletInitCodeHex = OWNER_VALIDATOR_CREATION_BYTECODE
                + "000000000000000000000000" + ownerHex;
        walletInitCodeBytes = Numeric.hexStringToByteArray(walletInitCodeHex);

        // Step 3: factoryCalldata = ABI-encoded deploy(walletInitCode, salt).
        // SALT is the same bytes32 used in the CREATE2 address derivation below.
        Function deployFn = new Function(
                "deploy",
                List.of(new DynamicBytes(walletInitCodeBytes), new Bytes32(SALT)),
                List.of());
        factoryCalldata = FunctionEncoder.encode(deployFn);

        // Step 4: Derive counterfactual wallet address in code (NOT hardcoded).
        // CREATE2: address = last 20 bytes of keccak256(0xff ++ factoryAddress ++ salt ++ keccak256(walletInitCode))
        byte[] factoryAddressBytes = Numeric.hexStringToByteArray(
                factoryAddress.startsWith("0x") ? factoryAddress.substring(2) : factoryAddress);
        byte[] walletInitCodeHash = Hash.sha3(walletInitCodeBytes);

        byte[] preimage = new byte[85]; // 1 (0xff) + 20 (factory) + 32 (salt) + 32 (initcode hash)
        preimage[0] = (byte) 0xff;
        System.arraycopy(factoryAddressBytes, 0, preimage, 1, 20);
        System.arraycopy(SALT, 0, preimage, 21, 32);
        System.arraycopy(walletInitCodeHash, 0, preimage, 53, 32);

        byte[] addressHash = Hash.sha3(preimage);
        derivedWalletAddress = "0x" + Numeric.toHexStringNoPrefix(
                Arrays.copyOfRange(addressHash, 12, 32));

        rawMessage = buildRawMessage(derivedWalletAddress);
        messageHash = Sign.getEthereumMessageHash(rawMessage.getBytes(StandardCharsets.UTF_8));

        chainClient = new Web3jChainClient(web3j);
    }

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

    private static byte[] buildInnerSig(ECKeyPair keyPair) {
        Sign.SignatureData sig = Sign.signPrefixedMessage(
                rawMessage.getBytes(StandardCharsets.UTF_8), keyPair);
        byte[] out = new byte[65];
        System.arraycopy(sig.getR(), 0, out, 0, Math.min(sig.getR().length, 32));
        System.arraycopy(sig.getS(), 0, out, 32, Math.min(sig.getS().length, 32));
        out[64] = sig.getV()[0];
        return out;
    }

    private static byte[] buildWrappedSig(byte[] innerSig) {
        byte[] factoryCalldataBytes = Numeric.hexStringToByteArray(
                factoryCalldata.startsWith("0x") ? factoryCalldata.substring(2) : factoryCalldata);
        // abi.encode(address factoryAddress, bytes factoryCalldata, bytes innerSig) ++ EIP-6492 magic
        String encodedHex = FunctionEncoder.encodeConstructor(List.of(
                new Address(factoryAddress),
                new DynamicBytes(factoryCalldataBytes),
                new DynamicBytes(innerSig)
        ));
        byte[] encodedBytes = Numeric.hexStringToByteArray(encodedHex);
        byte[] wrapped = new byte[encodedBytes.length + EIP6492_MAGIC_SUFFIX.length];
        System.arraycopy(encodedBytes, 0, wrapped, 0, encodedBytes.length);
        System.arraycopy(EIP6492_MAGIC_SUFFIX, 0, wrapped, encodedBytes.length, EIP6492_MAGIC_SUFFIX.length);
        return wrapped;
    }

    @Test
    void counterfactual_noCodeBeforeCall() {
        // Proves the wallet is genuinely not deployed before any validation call.
        String code = chainClient.getCode(derivedWalletAddress);
        assertThat(code).isEqualTo("0x");
    }

    @Test
    void counterfactual_validWrappedSignature_returnsTrue() {
        ECKeyPair ownerKey = ECKeyPair.create(Numeric.hexStringToByteArray(OWNER_PRIVATE_KEY));
        byte[] innerSig = buildInnerSig(ownerKey);
        byte[] wrappedSig = buildWrappedSig(innerSig);

        boolean result = chainClient.isValidSignatureDeployless(
                derivedWalletAddress, messageHash, wrappedSig);

        // 0x01 proves: derivation correct AND factory deploys to that address AND EIP-1271 validates.
        // The deployless eth_call does not persist the deploy — 0x01 is the proof, not post-call code.
        assertThat(result).isTrue();
    }

    @Test
    void counterfactual_forgedInnerSignature_returnsFalse() {
        // Forger key (account #1) produces a well-formed sig that recovers a non-owner address.
        ECKeyPair forgerKey = ECKeyPair.create(Numeric.hexStringToByteArray(FORGER_PRIVATE_KEY));
        byte[] innerSig = buildInnerSig(forgerKey);
        byte[] wrappedSig = buildWrappedSig(innerSig);

        boolean result = chainClient.isValidSignatureDeployless(
                derivedWalletAddress, messageHash, wrappedSig);

        // Wallet deploys, ecrecover recovers forger (≠ owner) → isValidSignature returns
        // non-magic → 0x00. Proves the deploy path does not rubber-stamp.
        assertThat(result).isFalse();
    }
}
