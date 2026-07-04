package com.w3auth.backend.challenge;

/**
 * Core port for rate limiting. Defines boundaries for checking request limits
 * without coupling to Spring, Redis, or servlet APIs.
 */
public interface RateLimiter {

    /**
     * Checks if the request is within rate limits.
     *
     * @param ip      the client's IP address (can be null/empty if unknown)
     * @param address the claimed wallet address/accountId (can be null/empty if unknown)
     * @throws RateLimitException if the limit is exceeded for either key
     */
    void checkLimit(String ip, String address) throws RateLimitException;
}
