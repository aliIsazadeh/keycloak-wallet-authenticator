package com.w3auth.backend.session;

import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    // 32-byte key encoded as Base64 (same value used in application.yml local-dev default)
    private static final String SECRET_B64 = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";
    private static final SecretKey SIGNING_KEY =
            Keys.hmacShaKeyFor(Base64.getDecoder().decode(SECRET_B64));

    private static final Duration TTL = Duration.ofMinutes(10);
    private static final String AUDIENCE = "wallet-auth";

    private static final Instant FIXED_NOW = Instant.parse("2026-06-20T12:00:00Z");
    private static final CaipAccountId ACCOUNT =
            CaipAccountId.of(Namespace.EIP155, "1", "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");

    private final JwtService service = new JwtService(new JwtPolicy(SIGNING_KEY, TTL, AUDIENCE));

    // ── claims correctness ────────────────────────────────────────────────────

    @Test
    void issue_subIsCAIP10String() {
        String token = service.issue(ACCOUNT, FIXED_NOW);
        Claims claims = parseClaims(token, SIGNING_KEY, FIXED_NOW);

        assertThat(claims.getSubject()).isEqualTo(ACCOUNT.toString());
    }

    @Test
    void issue_expIsIatPlusTtl() {
        String token = service.issue(ACCOUNT, FIXED_NOW);
        Claims claims = parseClaims(token, SIGNING_KEY, FIXED_NOW);

        Instant iat = claims.getIssuedAt().toInstant();
        Instant exp = claims.getExpiration().toInstant();

        assertThat(iat).isEqualTo(FIXED_NOW);
        assertThat(exp).isEqualTo(FIXED_NOW.plus(TTL));
    }

    @Test
    void issue_jtiIsPresent() {
        String token = service.issue(ACCOUNT, FIXED_NOW);
        Claims claims = parseClaims(token, SIGNING_KEY, FIXED_NOW);

        assertThat(claims.getId()).isNotBlank();
    }

    @Test
    void issue_audienceContainsConfiguredValue() {
        String token = service.issue(ACCOUNT, FIXED_NOW);
        Claims claims = parseClaims(token, SIGNING_KEY, FIXED_NOW);

        assertThat(claims.getAudience()).isEqualTo(Set.of(AUDIENCE));
    }

    // ── signature verification ────────────────────────────────────────────────

    @Test
    void issue_wrongSecret_failsVerification() {
        String token = service.issue(ACCOUNT, FIXED_NOW);

        SecretKey wrongKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(
                "enl4YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="));  // different key

        assertThatThrownBy(() -> parseClaims(token, wrongKey, FIXED_NOW))
                .isInstanceOf(JwtException.class);
    }

    // ── expiry ────────────────────────────────────────────────────────────────

    @Test
    void issue_clockAdvancedPastExpiry_parserThrowsExpiredJwtException() {
        String token = service.issue(ACCOUNT, FIXED_NOW);

        // Advance the clock one second past the expiry
        Instant afterExpiry = FIXED_NOW.plus(TTL).plusSeconds(1);

        assertThatThrownBy(() -> parseClaims(token, SIGNING_KEY, afterExpiry))
                .isInstanceOf(ExpiredJwtException.class);
    }

    // ── startup guard (tested at the configuration layer) ────────────────────
    // JwtConfiguration.jwtPolicy() enforces the 256-bit minimum before calling
    // Keys.hmacShaKeyFor(); see JwtConfigurationTest for that coverage.

    // ── helpers ───────────────────────────────────────────────────────────────

    /**
     * Parses the token using a synthetic clock fixed to {@code now}, so expiry
     * validation is reproducible without sleeping.
     */
    private static Claims parseClaims(String token, SecretKey key, Instant now) {
        return Jwts.parser()
                .verifyWith(key)
                .clock(() -> Date.from(now))
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
