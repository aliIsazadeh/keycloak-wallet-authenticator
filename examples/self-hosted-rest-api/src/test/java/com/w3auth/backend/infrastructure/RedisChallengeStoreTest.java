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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

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

    @Test
    void consume_concurrentThreads_exactlyOneSucceeds() throws InterruptedException {
        int threadCount = 8;
        Challenge challenge = sampleChallenge(Nonce.generate());
        store.store(challenge);

        CountDownLatch startGun = new CountDownLatch(1);
        List<Optional<Challenge>> results = new ArrayList<>(threadCount);
        for (int i = 0; i < threadCount; i++) results.add(null);
        List<AtomicReference<Throwable>> errors = new ArrayList<>(threadCount);
        List<Thread> threads = new ArrayList<>(threadCount);

        for (int i = 0; i < threadCount; i++) {
            final int idx = i;
            errors.add(new AtomicReference<>());
            Thread t = Thread.ofVirtual().start(() -> {
                try {
                    startGun.await();
                    results.set(idx, store.consume(challenge.nonce()));
                } catch (Throwable ex) {
                    errors.get(idx).set(ex);
                }
            });
            threads.add(t);
        }

        startGun.countDown();
        for (Thread t : threads) t.join(5_000);

        for (int i = 0; i < threadCount; i++) {
            assertThat(errors.get(i).get())
                    .as("thread %d threw an exception", i)
                    .isNull();
        }

        long successes = results.stream().filter(Optional::isPresent).count();
        long empties   = results.stream().filter(Optional::isEmpty).count();
        assertThat(successes).as("exactly one thread should get the challenge").isEqualTo(1);
        assertThat(empties).as("all other threads should get empty").isEqualTo(threadCount - 1);
    }

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
