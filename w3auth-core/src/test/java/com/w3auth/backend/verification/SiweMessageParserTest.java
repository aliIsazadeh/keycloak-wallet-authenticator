package com.w3auth.backend.verification;

import com.w3auth.backend.challenge.Challenge;
import com.w3auth.backend.challenge.SiweMessageFactory;
import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class SiweMessageParserTest {

    private static final CaipAccountId ACCOUNT =
            CaipAccountId.of(Namespace.EIP155, "1", "0xabc1234567890abc1234567890abc12345678901");

    private static final Instant ISSUED_AT = Instant.parse("2026-06-15T12:00:00Z");
    private static final Instant EXPIRES_AT = Instant.parse("2026-06-15T12:05:00Z");

    private static Challenge defaultChallenge() {
        return new Challenge(ACCOUNT, "abc123nonce", "example.com",
                "https://example.com/login", ISSUED_AT, EXPIRES_AT);
    }

    // ── round-trip: no statement (factory format, 10 lines) ───────────────────

    @Test
    void roundTrip_allFieldsMatchChallenge() {
        Challenge challenge = defaultChallenge();
        String message = SiweMessageFactory.create(challenge);

        SiweMessage parsed = SiweMessageParser.parse(message);

        assertThat(parsed.domain()).isEqualTo(challenge.domain());
        assertThat(parsed.address()).isEqualToIgnoringCase(challenge.account().address());
        assertThat(parsed.uri()).isEqualTo(challenge.uri());
        assertThat(parsed.version()).isEqualTo("1");
        assertThat(parsed.chainId()).isEqualTo(challenge.chainId());
        assertThat(parsed.nonce()).isEqualTo(challenge.nonce());
        assertThat(parsed.issuedAt()).isEqualTo(challenge.issuedAt());
        assertThat(parsed.expiresAt()).isEqualTo(challenge.expiresAt());
    }

    @Test
    void roundTrip_subSecondInstant_matchesChallenge() {
        Instant issuedAt = Instant.parse("2026-06-15T12:00:00.123456Z");
        Instant expiresAt = Instant.parse("2026-06-15T12:05:00.654321Z");
        Challenge challenge = new Challenge(ACCOUNT, "abc123nonce", "example.com",
                "https://example.com/login", issuedAt, expiresAt);

        SiweMessage parsed = SiweMessageParser.parse(SiweMessageFactory.create(challenge));

        assertThat(parsed.issuedAt()).isEqualTo(challenge.issuedAt());
        assertThat(parsed.expiresAt()).isEqualTo(challenge.expiresAt());
    }

    // ── EIP-4361 optional statement (11-line FTL format) ──────────────────────

    /**
     * Exact string the w3auth-login.ftl template builds in the browser, using
     * the Hardhat Account #0 address. This is the real-world fixture — if this
     * test breaks, sign-in from the Keycloak demo page will fail.
     */
    @Test
    void parse_withStatement_allFieldsMatch() {
        String message =
                "localhost wants you to sign in with your Ethereum account:\n" +
                "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266\n" +
                "\n" +
                "Sign in to Keycloak.\n" +
                "\n" +
                "URI: http://localhost:8080\n" +
                "Version: 1\n" +
                "Chain ID: 1\n" +
                "Nonce: abc123nonce\n" +
                "Issued At: 2026-06-15T12:00:00Z\n" +
                "Expiration Time: 2026-06-15T12:05:00Z";

        SiweMessage parsed = SiweMessageParser.parse(message);

        assertThat(parsed.domain()).isEqualTo("localhost");
        assertThat(parsed.address()).isEqualTo("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        assertThat(parsed.uri()).isEqualTo("http://localhost:8080");
        assertThat(parsed.version()).isEqualTo("1");
        assertThat(parsed.chainId()).isEqualTo("1");
        assertThat(parsed.nonce()).isEqualTo("abc123nonce");
        assertThat(parsed.issuedAt()).isEqualTo(Instant.parse("2026-06-15T12:00:00Z"));
        assertThat(parsed.expiresAt()).isEqualTo(Instant.parse("2026-06-15T12:05:00Z"));
    }

    @Test
    void parse_withStatement_carriage_returns_parsesSuccessfully() {
        String message =
                "localhost wants you to sign in with your Ethereum account:\r\n" +
                "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266\r\n" +
                "\r\n" +
                "Sign in to Keycloak.\r\n" +
                "\r\n" +
                "URI: http://localhost:8080\r\n" +
                "Version: 1\r\n" +
                "Chain ID: 1\r\n" +
                "Nonce: abc123nonce\r\n" +
                "Issued At: 2026-06-15T12:00:00Z\r\n" +
                "Expiration Time: 2026-06-15T12:05:00Z";

        SiweMessage parsed = SiweMessageParser.parse(message);

        assertThat(parsed.domain()).isEqualTo("localhost");
        assertThat(parsed.nonce()).isEqualTo("abc123nonce");
    }

    // ── malformed: too few lines ──────────────────────────────────────────────

    @Test
    void rejects_tooFewLines() {
        // Drop the last line (Expiration Time) — 9 lines
        String message = SiweMessageFactory.create(defaultChallenge());
        String truncated = message.substring(0, message.lastIndexOf('\n'));

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiweMessageParser.parse(truncated))
                .withMessageContaining("expected at least 10 lines");
    }

    // ── malformed: missing required field ─────────────────────────────────────

    @Test
    void rejects_missingUriPrefix() {
        String message = SiweMessageFactory.create(defaultChallenge())
                .replace("URI: https://example.com/login", "https://example.com/login");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiweMessageParser.parse(message))
                .withMessageContaining("URI: ");
    }

    @Test
    void rejects_missingExpirationTime() {
        // Replace the Expiration Time line with an unrecognised line so the total
        // line count stays at 10 and the "< 10" guard doesn't fire first.
        String message = SiweMessageFactory.create(defaultChallenge())
                .replaceAll("Expiration Time: .*", "Unknown-Field: something");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiweMessageParser.parse(message))
                .withMessageContaining("Expiration Time");
    }

    // ── malformed: unparseable timestamp ──────────────────────────────────────

    @Test
    void rejects_garbageTimestamp() {
        String message = SiweMessageFactory.create(defaultChallenge())
                .replace("Issued At: 2026-06-15T12:00:00Z", "Issued At: not-a-timestamp");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiweMessageParser.parse(message))
                .withMessageContaining("unparseable timestamp");
    }

    // ── malformed: blank line that should be blank isn't ─────────────────────

    @Test
    void rejects_nonEmptyBlankLine() {
        // Replace the first blank line (line index 2) with a space
        String message = SiweMessageFactory.create(defaultChallenge());
        String corrupted = message.replaceFirst("\n\n", "\n \n");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiweMessageParser.parse(corrupted))
                .withMessageContaining("must be blank");
    }

    // ── CRLF tolerance (no statement) ─────────────────────────────────────────

    @Test
    void parse_messageWithCarriageReturns_parsesSuccessfully() {
        String msgWithCr = "localhost wants you to sign in with your Ethereum account:\r\n" +
                "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266\r\n" +
                "\r\n" +
                "\r\n" +
                "URI: http://localhost:8080\r\n" +
                "Version: 1\r\n" +
                "Chain ID: 1\r\n" +
                "Nonce: testNonce123456\r\n" +
                "Issued At: 2026-06-15T12:00:00Z\r\n" +
                "Expiration Time: 2026-06-15T12:05:00Z";
        SiweMessage parsed = SiweMessageParser.parse(msgWithCr);
        assertThat(parsed.domain()).isEqualTo("localhost");
        assertThat(parsed.address()).isEqualTo("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        assertThat(parsed.nonce()).isEqualTo("testNonce123456");
    }
}
