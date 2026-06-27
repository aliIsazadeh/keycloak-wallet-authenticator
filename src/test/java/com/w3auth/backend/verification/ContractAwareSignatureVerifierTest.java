package com.w3auth.backend.verification;

import org.junit.jupiter.api.Test;
import org.web3j.abi.DefaultFunctionEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.DynamicBytes;
import org.web3j.abi.datatypes.Type;
import org.web3j.utils.Numeric;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ContractAwareSignatureVerifierTest {

    // ── in-memory fakes ───────────────────────────────────────────────────────

    /**
     * Fake ChainClient with separate controllable outcomes for each port method.
     * A {@code null} value for any {@code isValid*} field causes that method to throw
     * {@link RuntimeException} (simulates transport failure).
     */
    static class FakeChainClient implements ChainClient {
        private final String code;
        private final Boolean isValid1271;
        private final Boolean isValidDeployless;
        int getCodeCallCount = 0;
        int isValidCallCount = 0;
        int isValidDeploylessCallCount = 0;

        FakeChainClient(String code, Boolean isValid1271) {
            this(code, isValid1271, null);
        }

        FakeChainClient(String code, Boolean isValid1271, Boolean isValidDeployless) {
            this.code = code;
            this.isValid1271 = isValid1271;
            this.isValidDeployless = isValidDeployless;
        }

        @Override
        public String getCode(String address) {
            getCodeCallCount++;
            return code;
        }

        @Override
        public boolean isValidErc1271Signature(String contractAddress, byte[] hash, byte[] signature) {
            isValidCallCount++;
            if (isValid1271 == null) throw new RuntimeException("simulated transport failure");
            return isValid1271;
        }

        @Override
        public boolean isValidSignatureDeployless(String signer, byte[] hash, byte[] signature) {
            isValidDeploylessCallCount++;
            if (isValidDeployless == null) throw new RuntimeException("simulated deployless transport failure");
            return isValidDeployless;
        }
    }

    /** Stub EOA verifier — records invocations and returns a fixed VerifiedIdentity.
     *  Lets tests assert that the dispatcher delegates rather than reimplements ecrecover. */
    static class StubEoaVerifier implements SignatureVerifier {
        int callCount = 0;
        final VerifiedIdentity result;

        StubEoaVerifier(VerifiedIdentity result) {
            this.result = result;
        }

        @Override
        public VerifiedIdentity verify(VerificationRequest request) {
            callCount++;
            return result;
        }
    }

    // ── test fixtures ─────────────────────────────────────────────────────────

    private static final String ADDRESS = "0xabcdef1234567890abcdef1234567890abcdef12";
    private static final VerifiedIdentity EOA_IDENTITY = new VerifiedIdentity(ADDRESS);

    // Any 65-byte signature without the EIP-6492 trailer: 65 × 0xaa, hex-encoded.
    private static final String NON_6492_SIG = "0x" + "aa".repeat(65);

    // Any-length prefix (64 bytes of 0xbb) followed by the 32-byte EIP-6492 magic trailer.
    // Body = 64 bytes — intentionally malformed (< 96-byte minimum for a 3-word ABI head).
    private static final String EIP6492_SIG = "0x" + "bb".repeat(64)
            + "6492649264926492649264926492649264926492649264926492649264926492";

    // Valid EIP-6492 envelope whose body is produced by web3j DefaultFunctionEncoder —
    // a trusted ABI encoder independent of the Eip6492Envelope decoder under test.
    // Encodes: abi.encode(address(0xcafe...cafe), bytes(0xdeadbeef), bytes(0xbabe))
    // followed by the 32-byte EIP-6492 magic suffix.
    private static final String VALID_6492_SIG;
    static {
        try {
            @SuppressWarnings("rawtypes")
            List<Type> params = List.of(
                    new Address("0xcafecafecafecafecafecafecafecafecafecafe"),
                    new DynamicBytes(Numeric.hexStringToByteArray("deadbeef")),
                    new DynamicBytes(Numeric.hexStringToByteArray("babe")));
            String bodyHex = new DefaultFunctionEncoder().encodeParameters(params);
            VALID_6492_SIG = "0x" + bodyHex
                    + "6492649264926492649264926492649264926492649264926492649264926492";
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static SiweMessage siweMessage(String address) {
        return new SiweMessage(
                "example.com", address, "https://example.com", "1", "1",
                "abc123nonce",
                Instant.now().minusSeconds(60),
                Instant.now().plusSeconds(3600));
    }

    private static VerificationRequest request(String address, String signature) {
        return new VerificationRequest(siweMessage(address), "raw SIWE message text", signature);
    }

    // ── EOA-delegation branch ─────────────────────────────────────────────────

    @Test
    void emptyCode_delegatesToEoaVerifier() throws VerificationException {
        var stub = new StubEoaVerifier(EOA_IDENTITY);
        var fake = new FakeChainClient("0x", null);
        var dispatcher = new ContractAwareSignatureVerifier(stub, fake);

        dispatcher.verify(request(ADDRESS, NON_6492_SIG));

        assertThat(stub.callCount).isEqualTo(1);
    }

    @Test
    void eoaDelegation_resultPassedThrough() throws VerificationException {
        var stub = new StubEoaVerifier(EOA_IDENTITY);
        var fake = new FakeChainClient("0x", null);
        var dispatcher = new ContractAwareSignatureVerifier(stub, fake);

        VerifiedIdentity result = dispatcher.verify(request(ADDRESS, NON_6492_SIG));

        assertThat(result).isSameAs(EOA_IDENTITY);
    }

    // ── EIP-1271 contract branch ──────────────────────────────────────────────

    @Test
    void contractCode_validSignature_returnsClaimedAddressIdentity() throws VerificationException {
        var stub = new StubEoaVerifier(EOA_IDENTITY);
        var fake = new FakeChainClient("0x6080604052", true);
        var dispatcher = new ContractAwareSignatureVerifier(stub, fake);

        VerifiedIdentity result = dispatcher.verify(request(ADDRESS, NON_6492_SIG));

        assertThat(result.signerAddress()).isEqualToIgnoringCase(ADDRESS);
        assertThat(stub.callCount).isEqualTo(0);
    }

    @Test
    void contractCode_invalidSignature_throws() {
        var stub = new StubEoaVerifier(EOA_IDENTITY);
        var fake = new FakeChainClient("0x6080604052", false);
        var dispatcher = new ContractAwareSignatureVerifier(stub, fake);

        assertThatThrownBy(() -> dispatcher.verify(request(ADDRESS, NON_6492_SIG)))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("ERC-1271");
        assertThat(stub.callCount).isEqualTo(0);
    }

    // ── EIP-6492 dispatch ─────────────────────────────────────────────────────
    //
    // Before M3b commit 1: the 6492 branch threw "not yet supported" immediately.
    // After  M3b commit 1: the branch runs the well-formedness gate (Eip6492Envelope),
    //   then routes to ChainClient.isValidSignatureDeployless — behaviour-driven change,
    //   not test-driven-to-green.
    //
    // EIP6492_SIG has a 64-byte body (< 96-byte minimum) so it triggers the malformed-
    // envelope rejection, which is why these two structural tests still throw VerificationException
    // with "6492" in the message and still skip getCode.

    @Test
    void eip6492Suffix_malformedBody_throwsBeforeChainCall() {
        var stub = new StubEoaVerifier(EOA_IDENTITY);
        var fake = new FakeChainClient("0x", null);
        var dispatcher = new ContractAwareSignatureVerifier(stub, fake);

        assertThatThrownBy(() -> dispatcher.verify(request(ADDRESS, EIP6492_SIG)))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("6492");
        assertThat(fake.getCodeCallCount).isEqualTo(0);
        assertThat(fake.isValidDeploylessCallCount).isEqualTo(0);
    }

    @Test
    void eip6492Suffix_onAddressWithCode_stillRoutesTo6492PathNotEoa() {
        var stub = new StubEoaVerifier(EOA_IDENTITY);
        // Address has code AND signature has 6492 suffix: must still process the 6492 path,
        // not fall through to getCode → 1271. With the malformed body, throws before chain call.
        var fake = new FakeChainClient("0x6080604052", true, null);
        var dispatcher = new ContractAwareSignatureVerifier(stub, fake);

        assertThatThrownBy(() -> dispatcher.verify(request(ADDRESS, EIP6492_SIG)))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("6492");
        assertThat(fake.getCodeCallCount).isEqualTo(0);
        assertThat(fake.isValidCallCount).isEqualTo(0);
        assertThat(fake.isValidDeploylessCallCount).isEqualTo(0);
    }

    @Test
    void eip6492_wellFormedEnvelope_fakeTrue_returnsClaimedAddressIdentity()
            throws VerificationException {
        var stub = new StubEoaVerifier(EOA_IDENTITY);
        var fake = new FakeChainClient("0x", null, true);
        var dispatcher = new ContractAwareSignatureVerifier(stub, fake);

        VerifiedIdentity result = dispatcher.verify(request(ADDRESS, VALID_6492_SIG));

        assertThat(result.signerAddress()).isEqualToIgnoringCase(ADDRESS);
        assertThat(fake.getCodeCallCount).isEqualTo(0);
        assertThat(stub.callCount).isEqualTo(0);
        assertThat(fake.isValidDeploylessCallCount).isEqualTo(1);
    }

    @Test
    void eip6492_wellFormedEnvelope_fakeFalse_throws() {
        var stub = new StubEoaVerifier(EOA_IDENTITY);
        var fake = new FakeChainClient("0x", null, false);
        var dispatcher = new ContractAwareSignatureVerifier(stub, fake);

        assertThatThrownBy(() -> dispatcher.verify(request(ADDRESS, VALID_6492_SIG)))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("6492");
        assertThat(fake.isValidDeploylessCallCount).isEqualTo(1);
    }

    @Test
    void eip6492_wellFormedEnvelope_transportError_propagatesAsVerificationException() {
        var stub = new StubEoaVerifier(EOA_IDENTITY);
        // isValidDeployless == null → FakeChainClient throws RuntimeException
        var fake = new FakeChainClient("0x", null, null);
        var dispatcher = new ContractAwareSignatureVerifier(stub, fake);

        assertThatThrownBy(() -> dispatcher.verify(request(ADDRESS, VALID_6492_SIG)))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("transport error");
    }

    // ── malformed hex ─────────────────────────────────────────────────────────

    @Test
    void malformedHexSignature_throws() {
        var stub = new StubEoaVerifier(EOA_IDENTITY);
        var fake = new FakeChainClient("0x", null);
        var dispatcher = new ContractAwareSignatureVerifier(stub, fake);

        assertThatThrownBy(() -> dispatcher.verify(request(ADDRESS, "0xGGGG")))
                .isInstanceOf(VerificationException.class);
        assertThat(fake.getCodeCallCount).isEqualTo(0);
        assertThat(stub.callCount).isEqualTo(0);
    }

    // ── transport error propagation ───────────────────────────────────────────

    @Test
    void transportError_propagates() {
        var stub = new StubEoaVerifier(EOA_IDENTITY);
        // isValid == null → FakeChainClient.isValidErc1271Signature throws RuntimeException
        var fake = new FakeChainClient("0x6080604052", null);
        var dispatcher = new ContractAwareSignatureVerifier(stub, fake);

        // Must throw VerificationException (not swallow the transport error as false).
        assertThatThrownBy(() -> dispatcher.verify(request(ADDRESS, NON_6492_SIG)))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("transport error");
    }

    // ── EIP-6492 malformed-envelope rejection: load-bearing bounds checks ─────
    //
    // Both vectors are derived by mutating VALID_6492_SIG (produced by web3j
    // DefaultFunctionEncoder). FakeChainClient is configured with deployless=true so that
    // a missing bounds check surfaces as a wrong-accept (test failure), not a silent pass.

    @Test
    void eip6492_badOffset_throwsBeforeChainCall() {
        // Mutate word 2 (sigBytes[64..95]), the innerSig head offset.
        // Low 4 bytes (sigBytes[92..95]) change from 0x000000a0 (160) to 0x0000ffff (65535).
        // 65535 >= bodyLen (224): readOffset throws "out of range" before isValidSignatureDeployless.
        byte[] b = Numeric.hexStringToByteArray(VALID_6492_SIG.substring(2));
        b[92] = 0x00; b[93] = 0x00; b[94] = (byte) 0xff; b[95] = (byte) 0xff;
        String badOffsetSig = "0x" + Numeric.toHexStringNoPrefix(b);

        var stub = new StubEoaVerifier(EOA_IDENTITY);
        var fake = new FakeChainClient("0x", null, true);
        var dispatcher = new ContractAwareSignatureVerifier(stub, fake);

        assertThatThrownBy(() -> dispatcher.verify(request(ADDRESS, badOffsetSig)))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("6492");
        assertThat(fake.isValidDeploylessCallCount).isEqualTo(0);
        assertThat(fake.getCodeCallCount).isEqualTo(0);
    }

    @Test
    void eip6492_lengthOverrun_throwsBeforeChainCall() {
        // Mutate word 3 (sigBytes[96..127]), the factoryCalldata length.
        // Low 4 bytes (sigBytes[124..127]) change from 0x00000004 (4) to 0x0000ffff (65535).
        // validateDynamicField: 96 + 32 + 65535 = 65663 > bodyLen (224) → throws before chain call.
        byte[] b = Numeric.hexStringToByteArray(VALID_6492_SIG.substring(2));
        b[124] = 0x00; b[125] = 0x00; b[126] = (byte) 0xff; b[127] = (byte) 0xff;
        String lengthOverrunSig = "0x" + Numeric.toHexStringNoPrefix(b);

        var stub = new StubEoaVerifier(EOA_IDENTITY);
        var fake = new FakeChainClient("0x", null, true);
        var dispatcher = new ContractAwareSignatureVerifier(stub, fake);

        assertThatThrownBy(() -> dispatcher.verify(request(ADDRESS, lengthOverrunSig)))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("6492");
        assertThat(fake.isValidDeploylessCallCount).isEqualTo(0);
        assertThat(fake.getCodeCallCount).isEqualTo(0);
    }
}
