package com.w3auth.backend.session;

import javax.crypto.SecretKey;
import java.time.Duration;

/**
 * Immutable policy for access JWT issuance.
 *
 * <p>Constructed by the infrastructure layer (from config), then injected into
 * {@link JwtService}. Core — no Spring annotations.
 */
public record JwtPolicy(SecretKey signingKey, Duration ttl, String audience) {

    public JwtPolicy {
        if (signingKey == null) throw new IllegalArgumentException("signingKey must not be null");
        if (ttl == null || ttl.isZero() || ttl.isNegative()) throw new IllegalArgumentException("ttl must be positive");
        if (audience == null || audience.isBlank()) throw new IllegalArgumentException("audience must not be blank");
    }
}
