package com.w3auth.backend.challenge;

import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ChallengeTest {

    private static final CaipAccountId ACCOUNT =
            CaipAccountId.of(Namespace.EIP155, "1", "0xabc1234567890abc1234567890abc12345678901");

    @Test
    void exposesChainIdFromAccountReference() {
        Instant issuedAt = Instant.parse("2026-06-15T00:00:00Z");
        Challenge challenge = new Challenge(
                ACCOUNT, "nonce-value", "example.com", "https://example.com",
                issuedAt, issuedAt.plusSeconds(300));

        assertThat(challenge.chainId()).isEqualTo("1");
    }

    @Test
    void rejectsExpiresAtNotAfterIssuedAt() {
        Instant issuedAt = Instant.parse("2026-06-15T00:00:00Z");

        assertThatThrownBy(() -> new Challenge(
                ACCOUNT, "nonce-value", "example.com", "https://example.com", issuedAt, issuedAt))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> new Challenge(
                ACCOUNT, "nonce-value", "example.com", "https://example.com", issuedAt, issuedAt.minusSeconds(1)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsBlankNonce() {
        Instant issuedAt = Instant.parse("2026-06-15T00:00:00Z");

        assertThatThrownBy(() -> new Challenge(
                ACCOUNT, " ", "example.com", "https://example.com", issuedAt, issuedAt.plusSeconds(300)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
