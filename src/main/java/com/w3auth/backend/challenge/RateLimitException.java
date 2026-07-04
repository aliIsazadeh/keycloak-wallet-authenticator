package com.w3auth.backend.challenge;

/**
 * Thrown when a request exceeds the configured rate limits.
 */
public class RateLimitException extends RuntimeException {

    public RateLimitException(String message) {
        super(message);
    }
}
