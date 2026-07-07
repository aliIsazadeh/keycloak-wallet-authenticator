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

    // ── round-trip ────────────────────────────────────────────────────────────

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

    // ── malformed: wrong line count ───────────────────────────────────────────

    @Test
    void rejects_tooFewLines() {
        // Drop the last line (Expiration Time) — 9 lines
        String message = SiweMessageFactory.create(defaultChallenge());
        String truncated = message.substring(0, message.lastIndexOf('\n'));

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiweMessageParser.parse(truncated))
                .withMessageContaining("expected 10 lines");
    }

    @Test
    void rejects_tooManyLines() {
        String message = SiweMessageFactory.create(defaultChallenge()) + "\nextra line";

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiweMessageParser.parse(message))
                .withMessageContaining("expected 10 lines");
    }

    // ── malformed: missing prefix ─────────────────────────────────────────────

    @Test
    void rejects_missingUriPrefix() {
        String message = SiweMessageFactory.create(defaultChallenge())
                .replace("URI: https://example.com/login", "https://example.com/login");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiweMessageParser.parse(message))
                .withMessageContaining("URI: ");
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
        // The first blank line is the third line ("\n\n\n") — replace first "\n\n" with "\n \n"
        String corrupted = message.replaceFirst("\n\n", "\n \n");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiweMessageParser.parse(corrupted))
                .withMessageContaining("must be blank");
    }

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
