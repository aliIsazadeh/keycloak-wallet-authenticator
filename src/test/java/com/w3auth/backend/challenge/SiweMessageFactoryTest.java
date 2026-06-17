package com.w3auth.backend.challenge;

import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class SiweMessageFactoryTest {

    private static final CaipAccountId ACCOUNT =
            CaipAccountId.of(Namespace.EIP155, "1", "0xabc1234567890abc1234567890abc12345678901");

    @Test
    void buildsCanonicalEip4361Message() {
        Instant issuedAt = Instant.parse("2026-06-15T12:00:00Z");
        Instant expiresAt = Instant.parse("2026-06-15T12:05:00Z");
        Challenge challenge = new Challenge(
                ACCOUNT, "abc123nonce", "example.com", "https://example.com/login",
                issuedAt, expiresAt);

        String message = SiweMessageFactory.create(challenge);
        String[] lines = message.split("\n", -1);

        assertThat(lines).containsExactly(
                "example.com wants you to sign in with your Ethereum account:",
                "0xabc1234567890abc1234567890abc12345678901",
                "",
                "",
                "URI: https://example.com/login",
                "Version: 1",
                "Chain ID: 1",
                "Nonce: abc123nonce",
                "Issued At: 2026-06-15T12:00:00Z",
                "Expiration Time: 2026-06-15T12:05:00Z");
    }

    /**
     * Pins the output against a reference string built directly from the
     * EIP-4361 ABNF (not via the factory's own logic, to avoid a circular
     * assertion):
     *
     * <pre>
     * domain %s" wants you to sign in with your Ethereum account:" LF
     * address LF
     * LF
     * [ statement LF ]   -- absent in M0
     * LF
     * %s"URI: " uri LF
     * %s"Version: " version LF
     * %s"Chain ID: " chain-id LF
     * %s"Nonce: " nonce LF
     * %s"Issued At: " issued-at
     * [ LF %s"Expiration Time: " expiration-time ]
     * </pre>
     *
     * With no statement, "address LF" + "LF" + "LF" + "URI: ..." yields two
     * blank lines between the address and {@code URI:}. This matches the
     * reference implementation (spruceid/siwe {@code toMessage()}), which
     * also emits two blank lines when {@code statement} is unset.
     */
    @Test
    void matchesEip4361ReferenceFormatWithNoStatement() {
        Instant issuedAt = Instant.parse("2026-06-15T12:00:00Z");
        Instant expiresAt = Instant.parse("2026-06-15T12:05:00Z");
        Challenge challenge = new Challenge(
                ACCOUNT, "abc123nonce", "example.com", "https://example.com/login",
                issuedAt, expiresAt);

        String expected =
                "example.com wants you to sign in with your Ethereum account:\n"
                + "0xabc1234567890abc1234567890abc12345678901\n"
                + "\n"
                + "\n"
                + "URI: https://example.com/login\n"
                + "Version: 1\n"
                + "Chain ID: 1\n"
                + "Nonce: abc123nonce\n"
                + "Issued At: 2026-06-15T12:00:00Z\n"
                + "Expiration Time: 2026-06-15T12:05:00Z";

        assertThat(SiweMessageFactory.create(challenge)).isEqualTo(expected);
    }

    /**
     * The {@code Chain ID:} line reflects {@code account.reference()} — the
     * chain id the {@code CaipAccountId} was constructed with for THIS
     * request, not a value baked into the factory. In M1's
     * {@code RequestChallenge}, that {@code CaipAccountId} is built fresh
     * from the request's chainId every time; the wallet identity
     * ({@code identityKey()}) carries no chainId at all (see
     * {@code CaipAccountIdTest.identityKeyExcludesChainReference}). This test
     * uses a different chain (Polygon, 137) than the other tests in this
     * class (Ethereum mainnet, 1) to prove the field is wired through, not
     * hardcoded to "1".
     */
    @Test
    void chainIdLineReflectsAccountReferenceNotHardcoded() {
        CaipAccountId polygonAccount =
                CaipAccountId.of(Namespace.EIP155, "137", "0xabc1234567890abc1234567890abc12345678901");
        Challenge challenge = new Challenge(
                polygonAccount, "abc123nonce", "example.com", "https://example.com/login",
                Instant.parse("2026-06-15T12:00:00Z"), Instant.parse("2026-06-15T12:05:00Z"));

        String message = SiweMessageFactory.create(challenge);

        assertThat(message).contains("Chain ID: 137");
        assertThat(message).doesNotContain("Chain ID: 1\n");
    }

    @Test
    void usesCanonicalLowercaseAddressFromAccount() {
        CaipAccountId mixedCaseSource = CaipAccountId.of(Namespace.EIP155, "1", "0xABC1234567890ABC1234567890ABC12345678901");
        Challenge challenge = new Challenge(
                mixedCaseSource, "abc123nonce", "example.com", "https://example.com/login",
                Instant.parse("2026-06-15T12:00:00Z"), Instant.parse("2026-06-15T12:05:00Z"));

        String message = SiweMessageFactory.create(challenge);

        assertThat(message).contains("0xabc1234567890abc1234567890abc12345678901");
        assertThat(message).doesNotContain("0xABC1234567890ABC1234567890ABC12345678901");
    }
}
