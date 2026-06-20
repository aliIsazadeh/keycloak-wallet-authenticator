package com.w3auth.backend.session;

import com.w3auth.backend.identity.CaipAccountId;
import io.jsonwebtoken.Jwts;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Issues HS256 access JWTs for authenticated wallet accounts.
 *
 * <p>Core — no Spring annotations. Wired in {@code infrastructure.JwtConfiguration}.
 *
 * <p>Callers pass an explicit {@code issuedAt} so that the {@code iat} embedded in
 * the token and the {@code expiresAt} returned to the controller are derived from the
 * same instant, eliminating any clock-tick drift.
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

    /** Exposes the configured TTL so callers can derive {@code expiresAt} without re-parsing the token. */
    public Duration ttl() {
        return policy.ttl();
    }
}
