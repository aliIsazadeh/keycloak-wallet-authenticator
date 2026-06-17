package com.w3auth.backend.usecase;

import com.w3auth.backend.challenge.Challenge;
import com.w3auth.backend.challenge.ChallengePolicy;
import com.w3auth.backend.challenge.ChallengeStore;
import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

class RequestChallengeTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-06-15T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);

    private static final CaipAccountId ACCOUNT =
            CaipAccountId.of(Namespace.EIP155, "1", "0xabc1234567890abc1234567890abc12345678901");

    private static final ChallengePolicy POLICY =
            new ChallengePolicy("example.com", "https://example.com", Duration.ofMinutes(5));

    private final InMemoryChallengeStore challengeStore = new InMemoryChallengeStore();
    private final RequestChallenge useCase = new RequestChallenge(challengeStore, POLICY, FIXED_CLOCK);

    @Test
    void execute_storesAndReturnsChallengeWithCorrectFields() {
        Challenge challenge = useCase.execute(ACCOUNT);

        assertThat(challenge.account()).isEqualTo(ACCOUNT);
        assertThat(challenge.domain()).isEqualTo(POLICY.domain());
        assertThat(challenge.uri()).isEqualTo(POLICY.uri());
        assertThat(challenge.issuedAt()).isEqualTo(FIXED_NOW);
        assertThat(challenge.expiresAt()).isEqualTo(FIXED_NOW.plus(POLICY.nonceTtl()));
        assertThat(challengeStore.stored).containsKey(challenge.nonce());
    }

    @Test
    void execute_setsExpiresAtAsIssuedAtPlusNonceTtl() {
        Challenge challenge = useCase.execute(ACCOUNT);

        assertThat(challenge.expiresAt()).isEqualTo(challenge.issuedAt().plus(POLICY.nonceTtl()));
    }

    @Test
    void execute_generatesDifferentNonceOnEachCall() {
        // Nonce is base64url-no-pad over 16 raw bytes (128-bit CSPRNG).
        // The byte-length assertion guards against a future weakening of Nonce.generate()
        // (e.g. shorter nonce or a counter) that uniqueness alone would not catch.
        byte[] raw = Base64.getUrlDecoder().decode(useCase.execute(ACCOUNT).nonce());
        assertThat(raw).hasSize(16); // 128-bit CSPRNG nonce; uniqueness != unpredictability

        // 100 draws: collision probability with 128-bit nonce is negligible (~2e-27).
        Set<String> nonces = IntStream.range(0, 100)
                .mapToObj(i -> useCase.execute(ACCOUNT).nonce())
                .collect(Collectors.toSet());
        assertThat(nonces).hasSize(100);
    }

    // ---

    static class InMemoryChallengeStore implements ChallengeStore {
        final Map<String, Challenge> stored = new HashMap<>();

        @Override
        public void store(Challenge challenge) {
            stored.put(challenge.nonce(), challenge);
        }

        @Override
        public Optional<Challenge> consume(String nonce) {
            return Optional.ofNullable(stored.remove(nonce));
        }
    }
}
