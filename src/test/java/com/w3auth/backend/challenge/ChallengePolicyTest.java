package com.w3auth.backend.challenge;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ChallengePolicyTest {

    @Test
    void acceptsValidPolicy() {
        ChallengePolicy policy = new ChallengePolicy("example.com", "https://example.com", Duration.ofMinutes(5));

        assertThat(policy.domain()).isEqualTo("example.com");
        assertThat(policy.uri()).isEqualTo("https://example.com");
        assertThat(policy.nonceTtl()).isEqualTo(Duration.ofMinutes(5));
    }

    @Test
    void rejectsBlankDomain() {
        assertThatThrownBy(() -> new ChallengePolicy(" ", "https://example.com", Duration.ofMinutes(5)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsBlankUri() {
        assertThatThrownBy(() -> new ChallengePolicy("example.com", "", Duration.ofMinutes(5)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsNonPositiveNonceTtl() {
        assertThatThrownBy(() -> new ChallengePolicy("example.com", "https://example.com", Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> new ChallengePolicy("example.com", "https://example.com", Duration.ofSeconds(-1)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
