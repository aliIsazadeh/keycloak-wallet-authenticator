package com.w3auth.backend.challenge;

import java.time.Duration;

/**
 * Server-controlled policy for issued challenges.
 *
 * <p>Per the architecture, the server is authoritative on domain, nonce, and
 * expiry:
 * <ul>
 *   <li>{@code domain} and {@code uri} are the values the server fills into
 *       the SIWE message — never client-supplied.</li>
 *   <li>{@code nonceTtl} is the Redis TTL on the stored challenge. This is
 *       the <strong>real</strong> expiry gate (decision #8). The SIWE
 *       {@code Expiration Time} field is derived as
 *       {@code issuedAt + nonceTtl} — it mirrors the Redis TTL rather than
 *       being configured separately, so the two cannot drift apart.</li>
 * </ul>
 */
public record ChallengePolicy(String domain, String uri, Duration nonceTtl) {

    public ChallengePolicy {
        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException("domain must not be blank");
        }
        if (uri == null || uri.isBlank()) {
            throw new IllegalArgumentException("uri must not be blank");
        }
        if (nonceTtl == null || nonceTtl.isZero() || nonceTtl.isNegative()) {
            throw new IllegalArgumentException("nonceTtl must be positive");
        }
    }
}
