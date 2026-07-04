package com.w3auth.backend.infrastructure;

import com.w3auth.backend.challenge.RateLimitException;
import com.w3auth.backend.challenge.RateLimiter;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Redis-backed {@link RateLimiter}. Enforces sliding-window rate limits
 * using Redis atomic INCR and EXPIRE operations.
 */
@Component
public class RedisRateLimiter implements RateLimiter {

    private final StringRedisTemplate redisTemplate;

    public RedisRateLimiter(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void checkLimit(String ip, String address) throws RateLimitException {
        if (ip != null && !ip.isBlank()) {
            checkKeyLimit("ratelimit:ip:" + ip, 10, "IP rate limit exceeded");
        }
        if (address != null && !address.isBlank()) {
            checkKeyLimit("ratelimit:address:" + address, 5, "Address rate limit exceeded");
        }
    }

    private void checkKeyLimit(String key, int limit, String errorMessage) {
        Long count = redisTemplate.opsForValue().increment(key);
        if (count != null) {
            if (count == 1) {
                redisTemplate.expire(key, Duration.ofMinutes(1));
            }
            if (count > limit) {
                throw new RateLimitException(errorMessage);
            }
        }
    }
}
