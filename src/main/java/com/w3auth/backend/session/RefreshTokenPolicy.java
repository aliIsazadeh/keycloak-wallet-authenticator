package com.w3auth.backend.session;

import java.time.Duration;

/**
 * Immutable policy for refresh token issuance.
 * Core — no Spring annotations. Wired in {@code infrastructure.RefreshConfiguration}.
 */
public record RefreshTokenPolicy(Duration ttl) {

    public RefreshTokenPolicy {
        if (ttl == null || ttl.isZero() || ttl.isNegative())
            throw new IllegalArgumentException("refresh token ttl must be positive");
    }
}
