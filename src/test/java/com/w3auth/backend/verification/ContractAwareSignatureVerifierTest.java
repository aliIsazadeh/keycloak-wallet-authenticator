package com.w3auth.backend.verification;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ContractAwareSignatureVerifierTest {

    // ── in-memory fakes ───────────────────────────────────────────────────────

    /** Fake ChainClient; getCode returns a fixed value; isValidErc1271Signature returns a
     *  fixed boolean — or throws RuntimeException when isValid is null (transport-error case). */
    static class FakeChainClient implements ChainClient {
        private final String code;
        private final Boolean isValid;
        int getCodeCallCount = 0;
        int isValidCallCount = 0;

        FakeChainClient(String code, Boolean isValid) {
            this.code = code;
            this.isValid = isValid;
        }

        @Override
        public String getCode(String address) {
            getCodeCallCount++;
            return code;
        }

        @Override
        public boolean isValidErc1271Signature(String contractAddress, byte[] hash, byte[] signature) {
            isValidCallCount++;
            if (isValid == null) throw new RuntimeException("simulated transport failure");
            return isValid;
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
    // Trailer: 0x6492 repeated 16 times.
    private static final String EIP6492_SIG = "0x" + "bb".repeat(64)
            + "6492649264926492649264926492649264926492649264926492649264926492";

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

    // ── EIP-6492 stub ─────────────────────────────────────────────────────────

    @Test
    void eip6492Suffix_throwsNotSupported() {
        var stub = new StubEoaVerifier(EOA_IDENTITY);
        var fake = new FakeChainClient("0x", null);
        var dispatcher = new ContractAwareSignatureVerifier(stub, fake);

        assertThatThrownBy(() -> dispatcher.verify(request(ADDRESS, EIP6492_SIG)))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("6492");
        // Proves suffix check precedes getCode.
        assertThat(fake.getCodeCallCount).isEqualTo(0);
    }

    @Test
    void eip6492Suffix_onAddressWithCode_stillThrowsBeforeGetCode() {
        var stub = new StubEoaVerifier(EOA_IDENTITY);
        // Address has code AND signature has 6492 suffix: must still throw 6492, not misroute.
        var fake = new FakeChainClient("0x6080604052", true);
        var dispatcher = new ContractAwareSignatureVerifier(stub, fake);

        assertThatThrownBy(() -> dispatcher.verify(request(ADDRESS, EIP6492_SIG)))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("6492");
        assertThat(fake.getCodeCallCount).isEqualTo(0);
        assertThat(fake.isValidCallCount).isEqualTo(0);
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
}
