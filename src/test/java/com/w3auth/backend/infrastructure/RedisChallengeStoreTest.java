package com.w3auth.backend.infrastructure;

import com.w3auth.backend.challenge.Challenge;
import com.w3auth.backend.challenge.ChallengePolicy;
import com.w3auth.backend.challenge.Nonce;
import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
class RedisChallengeStoreTest {

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

    private static StringRedisTemplate redisTemplate;

    @BeforeAll
    static void setUpRedis() {
        LettuceConnectionFactory connectionFactory =
                new LettuceConnectionFactory(REDIS.getHost(), REDIS.getMappedPort(6379));
        connectionFactory.afterPropertiesSet();
        redisTemplate = new StringRedisTemplate(connectionFactory);
        redisTemplate.afterPropertiesSet();
    }

    private final ChallengePolicy policy =
            new ChallengePolicy("example.com", "https://example.com", Duration.ofMinutes(5));
    private final RedisChallengeStore store =
            new RedisChallengeStore(redisTemplate, new ObjectMapper(), policy);

    private Challenge sampleChallenge(String nonce) {
        CaipAccountId account =
                CaipAccountId.of(Namespace.EIP155, "1", "0xabc1234567890abc1234567890abc12345678901");
        Instant issuedAt = Instant.parse("2026-06-15T12:00:00Z");
        return new Challenge(account, nonce, "example.com", "https://example.com/login",
                issuedAt, issuedAt.plus(policy.nonceTtl()));
    }

    @Test
    void storeThenConsumeReturnsTheChallenge() {
        Challenge challenge = sampleChallenge(Nonce.generate());

        store.store(challenge);
        Optional<Challenge> consumed = store.consume(challenge.nonce());

        assertThat(consumed).contains(challenge);
    }

    // TODO: concurrency test — N threads consume same nonce, assert exactly one success (regression guard for atomicity)

    @Test
    void consumeIsSingleUse() {
        Challenge challenge = sampleChallenge(Nonce.generate());
        store.store(challenge);

        assertThat(store.consume(challenge.nonce())).isPresent();
        assertThat(store.consume(challenge.nonce())).isEmpty();
    }

    @Test
    void consumeOfUnknownNonceReturnsEmpty() {
        assertThat(store.consume(Nonce.generate())).isEmpty();
    }

    @Test
    void storeSetsTtlOnTheKey() {
        Challenge challenge = sampleChallenge(Nonce.generate());

        store.store(challenge);

        Long ttlSeconds = redisTemplate.getExpire(RedisChallengeStore.KEY_PREFIX + challenge.nonce(), TimeUnit.SECONDS);
        assertThat(ttlSeconds).isNotNull();
        assertThat(ttlSeconds).isPositive();
        assertThat(ttlSeconds).isLessThanOrEqualTo(policy.nonceTtl().toSeconds());
    }
}
