package com.w3auth.backend.session;

import com.w3auth.backend.identity.CaipAccountId;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Issues and parses HS256 access JWTs for authenticated wallet accounts.
 *
 * <p>Core — no Spring annotations. Wired in {@code infrastructure.JwtConfiguration}.
 *
 * <p>Callers pass an explicit {@code now} so that clock-sensitive operations
 * (issuance timestamp, expiry validation) are fully reproducible in tests.
 */
public class JwtService {

    private final JwtPolicy policy;

    public JwtService(JwtPolicy policy) {
        this.policy = policy;
    }

    /**
     * Issues a signed access JWT.
     *
     * @param account  the authenticated wallet — becomes the {@code sub} claim (CAIP-10 string)
     * @param issuedAt the moment of issuance (caller-controlled for testability)
     * @return the compact, signed JWT string
     */
    public String issue(CaipAccountId account, Instant issuedAt) {
        Instant exp = issuedAt.plus(policy.ttl());
        return Jwts.builder()
                .subject(account.toString())
                .id(UUID.randomUUID().toString())
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(exp))
                .audience().add(policy.audience()).and()
                .signWith(policy.signingKey())
                .compact();
    }

    /**
     * Parses and validates a compact JWT string.
     *
     * <p>Validates signature, expiry (relative to {@code now}), and audience.
     *
     * @param token the compact JWT string
     * @param now   the clock instant to use for expiry validation
     * @return the verified claims payload
     * @throws JwtException if the token is expired, has a bad signature, is malformed,
     *                      or fails audience validation
     */
    public Claims parse(String token, Instant now) {
        return Jwts.parser()
                .verifyWith(policy.signingKey())
                .clock(() -> Date.from(now))
                .requireAudience(policy.audience())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /** Exposes the configured TTL so callers can derive {@code expiresAt} without re-parsing the token. */
    public Duration ttl() {
        return policy.ttl();
    }
}
