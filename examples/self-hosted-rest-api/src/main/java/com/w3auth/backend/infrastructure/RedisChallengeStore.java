package com.w3auth.backend.infrastructure;

import com.w3auth.backend.challenge.Challenge;
import com.w3auth.backend.challenge.ChallengePolicy;
import com.w3auth.backend.challenge.ChallengeStore;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.util.Optional;

/**
 * Redis-backed {@link ChallengeStore}. Each challenge is stored as JSON at
 * {@code challenge:{nonce}} with a TTL from {@link ChallengePolicy#nonceTtl()};
 * {@link #consume(String)} retrieves and deletes the key atomically
 * (Redis {@code GETDEL}) so a nonce can only ever be consumed once.
 */
@Component
public class RedisChallengeStore implements ChallengeStore {

    static final String KEY_PREFIX = "challenge:";

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;
    private final ChallengePolicy policy;

    public RedisChallengeStore(StringRedisTemplate redisTemplate, ObjectMapper objectMapper, ChallengePolicy policy) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
        this.policy = policy;
    }

    @Override
    public void store(Challenge challenge) {
        String json = objectMapper.writeValueAsString(RedisChallengeRecord.from(challenge));
        redisTemplate.opsForValue().set(keyFor(challenge.nonce()), json, policy.nonceTtl());
    }

    @Override
    public Optional<Challenge> consume(String nonce) {
        String json = redisTemplate.opsForValue().getAndDelete(keyFor(nonce));
        if (json == null) {
            return Optional.empty();
        }
        return Optional.of(objectMapper.readValue(json, RedisChallengeRecord.class).toChallenge());
    }

    private static String keyFor(String nonce) {
        return KEY_PREFIX + nonce;
    }
}
