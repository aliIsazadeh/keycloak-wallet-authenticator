package com.w3auth.backend.session;

/**
 * Thrown by {@link RefreshTokenStore} for all failure cases: unknown token, expired,
 * revoked family, reuse detected, or lost concurrent race.
 *
 * <p>Callers in the API layer map this to HTTP 401.
 */
public class RefreshTokenException extends RuntimeException {

    public RefreshTokenException(String message) {
        super(message);
    }
}
