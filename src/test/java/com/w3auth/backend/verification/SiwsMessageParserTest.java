package com.w3auth.backend.verification;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class SiwsMessageParserTest {

    // Canonical spec-derived message — NOT produced by any factory (no SIWS factory exists yet).
    // Two blank lines between the address and "URI: " (lines 2 and 3 both empty).
    private static final String CANONICAL =
            "example.com wants you to sign in with your Solana account:\n" +
            "7S3P4HxJpyyigGzodYwHtCxZyUQe9JiBMHyRWXArAaKv\n" +
            "\n" +
            "\n" +
            "URI: https://example.com/login\n" +
            "Version: 1\n" +
            "Chain ID: mainnet\n" +
            "Nonce: oNCEHm5jzQU2WvuBB\n" +
            "Issued At: 2026-06-15T12:00:00Z\n" +
            "Expiration Time: 2026-06-15T12:05:00Z";

    // ── happy path ────────────────────────────────────────────────────────────

    @Test
    void parsesCanonicalMessage_allFieldsMatchExpectedRawValues() {
        SiwsMessage parsed = SiwsMessageParser.parse(CANONICAL);

        assertThat(parsed.domain()).isEqualTo("example.com");
        assertThat(parsed.address()).isEqualTo("7S3P4HxJpyyigGzodYwHtCxZyUQe9JiBMHyRWXArAaKv");
        assertThat(parsed.uri()).isEqualTo("https://example.com/login");
        assertThat(parsed.version()).isEqualTo("1");
        assertThat(parsed.chainId()).isEqualTo("mainnet");
        assertThat(parsed.nonce()).isEqualTo("oNCEHm5jzQU2WvuBB");
        assertThat(parsed.issuedAt()).isEqualTo(Instant.parse("2026-06-15T12:00:00Z"));
        assertThat(parsed.expiresAt()).isEqualTo(Instant.parse("2026-06-15T12:05:00Z"));
    }

    @Test
    void subSecondInstants_roundTrip() {
        String message = CANONICAL
                .replace("Issued At: 2026-06-15T12:00:00Z", "Issued At: 2026-06-15T12:00:00.123456Z")
                .replace("Expiration Time: 2026-06-15T12:05:00Z", "Expiration Time: 2026-06-15T12:05:00.654321Z");

        SiwsMessage parsed = SiwsMessageParser.parse(message);

        assertThat(parsed.issuedAt()).isEqualTo(Instant.parse("2026-06-15T12:00:00.123456Z"));
        assertThat(parsed.expiresAt()).isEqualTo(Instant.parse("2026-06-15T12:05:00.654321Z"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"devnet", "testnet"})
    void accepts_validClusterIds(String cluster) {
        String message = CANONICAL.replace("Chain ID: mainnet", "Chain ID: " + cluster);

        SiwsMessage parsed = SiwsMessageParser.parse(message);

        assertThat(parsed.chainId()).isEqualTo(cluster);
    }

    // ── chainId rejection ─────────────────────────────────────────────────────

    @Test
    void rejects_chainId_numeric() {
        String message = CANONICAL.replace("Chain ID: mainnet", "Chain ID: 1");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiwsMessageParser.parse(message))
                .withMessageContaining("Chain ID must be one of");
    }

    @Test
    void rejects_chainId_prefixed() {
        String message = CANONICAL.replace("Chain ID: mainnet", "Chain ID: solana:mainnet");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiwsMessageParser.parse(message))
                .withMessageContaining("Chain ID must be one of");
    }

    @Test
    void rejects_chainId_localnet() {
        String message = CANONICAL.replace("Chain ID: mainnet", "Chain ID: localnet");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiwsMessageParser.parse(message))
                .withMessageContaining("Chain ID must be one of");
    }

    // ── wrong namespace ───────────────────────────────────────────────────────

    @Test
    void rejects_ethereumSuffix() {
        String message = CANONICAL.replace(
                " wants you to sign in with your Solana account:",
                " wants you to sign in with your Ethereum account:");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiwsMessageParser.parse(message))
                .withMessageContaining("line 0 must end with");
    }

    // ── wrong line count ──────────────────────────────────────────────────────

    @Test
    void rejects_tooFewLines() {
        String truncated = CANONICAL.substring(0, CANONICAL.lastIndexOf('\n'));

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiwsMessageParser.parse(truncated))
                .withMessageContaining("expected 10 lines");
    }

    @Test
    void rejects_tooManyLines_walletExtras() {
        // Wallet-built messages may carry Not Before / Request ID / Resources — all refused.
        String withExtras = CANONICAL +
                "\nNot Before: 2026-06-15T12:01:00Z\nRequest ID: x\nResources:\n- https://example.com/a";

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiwsMessageParser.parse(withExtras))
                .withMessageContaining("expected 10 lines");
    }

    // ── blank-line discipline ─────────────────────────────────────────────────

    @Test
    void rejects_nonBlankLineThatShouldBeBlank() {
        // Replace the first "\n\n" (lines 2 and 3 separator) with "\n \n"
        String corrupted = CANONICAL.replaceFirst("\n\n", "\n \n");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiwsMessageParser.parse(corrupted))
                .withMessageContaining("must be blank");
    }

    // ── missing prefix ────────────────────────────────────────────────────────

    @Test
    void rejects_missingUriPrefix() {
        String message = CANONICAL.replace("URI: https://example.com/login", "https://example.com/login");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiwsMessageParser.parse(message))
                .withMessageContaining("URI: ");
    }

    // ── bad timestamp ─────────────────────────────────────────────────────────

    @Test
    void rejects_garbageTimestamp() {
        String message = CANONICAL.replace("Issued At: 2026-06-15T12:00:00Z", "Issued At: not-a-timestamp");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiwsMessageParser.parse(message))
                .withMessageContaining("unparseable timestamp");
    }

    // ── null input ────────────────────────────────────────────────────────────

    @Test
    void rejects_nullInput() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> SiwsMessageParser.parse(null))
                .withMessageContaining("must not be null");
    }
}
