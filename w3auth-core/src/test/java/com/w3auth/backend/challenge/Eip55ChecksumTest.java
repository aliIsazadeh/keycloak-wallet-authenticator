package com.w3auth.backend.challenge;

import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * EIP-55 checksum golden vectors for {@link SiweMessageFactory}.
 *
 * <p>{@link CaipAccountId} canonicalizes EVM addresses to lowercase. The factory MUST apply
 * EIP-55 checksum casing at embed time so that wallets (MetaMask, Rainbow, etc.) that
 * enforce EIP-55 do not reject the challenge message. These tests pin the expected
 * checksummed forms from the EIP-55 spec directly — no circular dependency on
 * {@code Keys.toChecksumAddress} in the assertion.
 */
class Eip55ChecksumTest {

    private static final Instant ISSUED  = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant EXPIRES = Instant.parse("2026-01-01T00:05:00Z");

    /** Returns the address line (second line) of the SIWE message for a given CAIP-10 string. */
    private static String siweAddressLine(String caip10) {
        CaipAccountId account = CaipAccountId.parse(caip10);
        Challenge challenge = new Challenge(account, "testnonce1a", "example.com",
                "https://example.com", ISSUED, EXPIRES);
        return SiweMessageFactory.create(challenge).split("\n", -1)[1];
    }

    // -------------------------------------------------------------------------
    // EIP-55 spec golden vectors — hardcoded expected checksummed forms
    // -------------------------------------------------------------------------

    @Test
    void eip55_vector1_checksummedInSiweMessage() {
        String line = siweAddressLine("eip155:1:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
        assertThat(line).isEqualTo("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }

    @Test
    void eip55_vector2_checksummedInSiweMessage() {
        String line = siweAddressLine("eip155:1:0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359");
        assertThat(line).isEqualTo("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
    }

    @Test
    void eip55_vector3_checksummedInSiweMessage() {
        String line = siweAddressLine("eip155:1:0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb");
        assertThat(line).isEqualTo("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB");
    }

    @Test
    void eip55_vector4_checksummedInSiweMessage() {
        String line = siweAddressLine("eip155:1:0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb");
        assertThat(line).isEqualTo("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb");
    }

    // -------------------------------------------------------------------------
    // The critical case: CaipAccountId stores lowercase; factory must re-checksum
    // -------------------------------------------------------------------------

    /**
     * A wallet-submitted accountId may arrive in all-caps (some SDKs normalise to uppercase).
     * {@link CaipAccountId} canonicalises it to lowercase; {@link SiweMessageFactory} must
     * then apply EIP-55 at embed time — not trust the stored lowercase form.
     * Strict wallets (MetaMask confirmed) reject messages whose address is not checksummed.
     */
    @Test
    void eip55_uppercaseInputLowercasedByCaip_checksummedInMessage() {
        CaipAccountId account = CaipAccountId.of(Namespace.EIP155, "1",
                "0xFB6916095CA1DF60BB79CE92CE3EA74C37C5D359");
        // CaipAccountId canonicalises to lowercase
        assertThat(account.address()).isEqualTo("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359");

        Challenge challenge = new Challenge(account, "testnonce1a", "example.com",
                "https://example.com", ISSUED, EXPIRES);
        String line = SiweMessageFactory.create(challenge).split("\n", -1)[1];

        // The message must embed the EIP-55 checksummed form, not the canonical lowercase form
        assertThat(line).isEqualTo("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
    }
}
