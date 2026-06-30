package com.w3auth.backend.verification;

import com.w3auth.backend.identity.SolanaPublicKey;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * RFC 8032 §7.1 TEST 2 vector — externally verified, not generated.
 * Public key hex confirmed against two independent base58 encoders
 * (Python base58, Node bs58) to produce ADDRESS_B58.
 */
class SolanaSignatureVerifierTest {

    // RFC 8032 §7.1, TEST 2 — Ed25519 public key
    private static final String PUBKEY_HEX =
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    // Base58-encoding of the 32 bytes above (Solana address form)
    private static final String ADDRESS_B58 =
            "586Z7H2vpX9qNhN2T4e9Utugie3ogjbxzGaMtM3E6HR5";
    // RFC 8032 §7.1, TEST 2 — message (single byte 0x72)
    private static final String MESSAGE_HEX = "72";
    // RFC 8032 §7.1, TEST 2 — Ed25519 signature (64 bytes)
    private static final String SIGNATURE_HEX =
            "92a009a9f0d4cab8720e820b5f642540" +
            "a2b27b5416503f8fb3762223ebdb69da" +
            "085ac1e43e15996e458f3613d0f11d8c" +
            "387b2eaeb4302aeeb00d291612bb0c00";

    // RFC 8032 §7.1, TEST 1 — pubkey base58-encoded; confirmed with two independent tools
    // (Python base58, Node bs58). Used to prove the TEST 2 signature does not verify
    // against a different valid key (clean-false, not structural failure).
    private static final String SECOND_ADDRESS = "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z";

    private static final String CLEAN_FALSE_MSG = "signature does not verify against public key";
    private static final String STRUCTURAL_MSG_PREFIX = "signature must be 64 bytes, got ";

    private final SolanaSignatureVerifier verifier = new SolanaSignatureVerifier();

    // -------------------------------------------------------------------------
    // Fixture correctness guard — must pass before any crypto test is meaningful
    // -------------------------------------------------------------------------

    @Test
    void decodeSanity_addressDecodesToRfcPubkeyBytes() {
        byte[] decoded = SolanaPublicKey.decode(ADDRESS_B58);
        assertThat(decoded).isEqualTo(hexToBytes(PUBKEY_HEX));
    }

    // -------------------------------------------------------------------------
    // Happy path
    // -------------------------------------------------------------------------

    @Test
    void acceptValid_rfcTest2VectorVerifies() throws VerificationException {
        VerifiedIdentity result = verifier.verify(
                hexToBytes(MESSAGE_HEX), hexToBytes(SIGNATURE_HEX), ADDRESS_B58);

        assertThat(result.signerAddress()).isEqualTo(ADDRESS_B58);
    }

    // -------------------------------------------------------------------------
    // Reject: crypto false (well-formed inputs, signature does not match)
    // -------------------------------------------------------------------------

    @Test
    void rejectTamperedMessage_throwsCleanFalse() {
        byte[] tampered = hexToBytes(MESSAGE_HEX);
        tampered[0] = (byte) (tampered[0] ^ 0x01);  // flip one bit

        assertThatThrownBy(() ->
                verifier.verify(tampered, hexToBytes(SIGNATURE_HEX), ADDRESS_B58))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining(CLEAN_FALSE_MSG);
    }

    @Test
    void rejectTamperedSignature_throwsCleanFalse() {
        byte[] tampered = hexToBytes(SIGNATURE_HEX);
        tampered[0] = (byte) (tampered[0] ^ 0x01);  // flip one bit; still 64 bytes

        assertThatThrownBy(() ->
                verifier.verify(hexToBytes(MESSAGE_HEX), tampered, ADDRESS_B58))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining(CLEAN_FALSE_MSG);
    }

    @Test
    void rejectWrongKey_differentValidAddressThrowsCleanFalse() {
        // TEST 2 signature verified against TEST 1 key — well-formed inputs, Ed25519 returns false.
        assertThatThrownBy(() ->
                verifier.verify(hexToBytes(MESSAGE_HEX), hexToBytes(SIGNATURE_HEX), SECOND_ADDRESS))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining(CLEAN_FALSE_MSG);
    }

    // -------------------------------------------------------------------------
    // Reject: structural (wrong length / malformed inputs)
    // -------------------------------------------------------------------------

    @Test
    void rejectShortSignature_throwsStructural() {
        byte[] short63 = new byte[63];

        assertThatThrownBy(() ->
                verifier.verify(hexToBytes(MESSAGE_HEX), short63, ADDRESS_B58))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining(STRUCTURAL_MSG_PREFIX + "63");
    }

    @Test
    void rejectLongSignature_throwsStructural() {
        byte[] long65 = new byte[65];

        assertThatThrownBy(() ->
                verifier.verify(hexToBytes(MESSAGE_HEX), long65, ADDRESS_B58))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining(STRUCTURAL_MSG_PREFIX + "65");
    }

    @Test
    void rejectMalformedAddress_nonBase58() {
        assertThatThrownBy(() ->
                verifier.verify(hexToBytes(MESSAGE_HEX), hexToBytes(SIGNATURE_HEX), "0xinvalidaddress!"))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("invalid Solana address");
    }

    @Test
    void rejectMalformedAddress_wrongLengthBase58() {
        // Valid base58 characters but decodes to fewer than 32 bytes
        assertThatThrownBy(() ->
                verifier.verify(hexToBytes(MESSAGE_HEX), hexToBytes(SIGNATURE_HEX), "7S3P4H"))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("invalid Solana address");
    }

    @Test
    void rejectNullMessage() {
        assertThatThrownBy(() ->
                verifier.verify(null, hexToBytes(SIGNATURE_HEX), ADDRESS_B58))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("message must not be null");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
