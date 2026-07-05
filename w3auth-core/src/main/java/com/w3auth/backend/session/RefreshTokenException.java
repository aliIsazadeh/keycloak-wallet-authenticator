package com.w3auth.backend.session;

/**
 * Thrown by {@link RefreshTokenStore} for all failure cases: unknown token, expired,
 * revoked family, reuse detected, or lost concurrent race.
 *
 * <p>Callers in the API layer map this to HTTP 401. The {@link Reason} lets the handler
 * branch on log level without inspecting the message string or leaking the reason to the wire.
 */
public class RefreshTokenException extends RuntimeException {

    public enum Reason {
        NOT_FOUND,
        EXPIRED,
        FAMILY_REVOKED,
        REUSE_DETECTED,
        RACE_LOST
    }

    private final Reason reason;

    public RefreshTokenException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
