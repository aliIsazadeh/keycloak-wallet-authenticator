package com.w3auth.backend.usecase;

import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import com.w3auth.backend.identity.WalletIdentity;
import com.w3auth.backend.identity.WalletIdentityStore;
import com.w3auth.backend.session.JwtPolicy;
import com.w3auth.backend.session.JwtService;
import com.w3auth.backend.session.RefreshToken;
import com.w3auth.backend.session.RefreshTokenException;
import com.w3auth.backend.session.RefreshTokenStore;
import com.w3auth.backend.session.TokenGrant;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RefreshSessionTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-06-23T10:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);

    private static final SecretKey SIGNING_KEY =
            Keys.hmacShaKeyFor(Base64.getDecoder().decode("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="));
    private static final Duration JWT_TTL = Duration.ofMinutes(10);
    private static final JwtService JWT_SERVICE =
            new JwtService(new JwtPolicy(SIGNING_KEY, JWT_TTL, "wallet-auth"));

    private static final String ADDRESS = "0xabc1234567890abc1234567890abc12345678901";
    private static final CaipAccountId ACCOUNT = CaipAccountId.of(Namespace.EIP155, "1", ADDRESS);

    private static final UUID IDENTITY_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID FAMILY_ID   = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final UUID TOKEN_ID    = UUID.fromString("00000000-0000-0000-0000-000000000003");

    private static final WalletIdentity IDENTITY = new WalletIdentity(
            IDENTITY_ID, ACCOUNT.identityKey(), "active", FIXED_NOW, FIXED_NOW);

    private static final String RAW_REFRESH_TOKEN = "test-raw-refresh-token";
    private static final RefreshToken REFRESH_TOKEN_ROW = new RefreshToken(
            TOKEN_ID, FAMILY_ID, IDENTITY_ID,
            "fakehash", null,
            FIXED_NOW.plus(Duration.ofDays(30)), null, FIXED_NOW);
    private static final TokenGrant TOKEN_GRANT = new TokenGrant(RAW_REFRESH_TOKEN, REFRESH_TOKEN_ROW);

    // ── happy path ────────────────────────────────────────────────────────────

    @Test
    void execute_validToken_returnsResultWithRotatedTokenAndJwt() {
        RefreshSession useCase = new RefreshSession(
                new FixedGrantStore(TOKEN_GRANT),
                new FixedIdentityStore(Optional.of(IDENTITY)),
                JWT_SERVICE,
                FIXED_CLOCK);

        RefreshResult result = useCase.execute(RAW_REFRESH_TOKEN);

        assertThat(result.refreshToken()).isEqualTo(RAW_REFRESH_TOKEN);
        assertThat(result.expiresAt()).isEqualTo(FIXED_NOW.plus(JWT_TTL));

        Claims claims = parseClaims(result.token(), SIGNING_KEY, FIXED_NOW);
        assertThat(claims.getSubject()).isEqualTo(IDENTITY.identityKey().toJwtSubject());
    }

    // ── rotate failure propagates ─────────────────────────────────────────────

    @Test
    void execute_rotateThrows_propagates() {
        RefreshTokenException cause =
                new RefreshTokenException(RefreshTokenException.Reason.EXPIRED, "refresh token expired");
        FixedIdentityStore identityStore = new FixedIdentityStore(Optional.of(IDENTITY));

        RefreshSession useCase = new RefreshSession(
                new ThrowingStore(cause),
                identityStore,
                JWT_SERVICE,
                FIXED_CLOCK);

        assertThatThrownBy(() -> useCase.execute(RAW_REFRESH_TOKEN))
                .isSameAs(cause)
                .isInstanceOf(RefreshTokenException.class)
                .satisfies(ex -> assertThat(((RefreshTokenException) ex).reason())
                        .isEqualTo(RefreshTokenException.Reason.EXPIRED));

        assertThat(identityStore.findByIdCallCount).isZero();
    }

    // ── identity missing after rotate ─────────────────────────────────────────

    @Test
    void execute_identityMissingAfterRotate_throwsNotFound() {
        RefreshSession useCase = new RefreshSession(
                new FixedGrantStore(TOKEN_GRANT),
                new FixedIdentityStore(Optional.empty()),
                JWT_SERVICE,
                FIXED_CLOCK);

        assertThatThrownBy(() -> useCase.execute(RAW_REFRESH_TOKEN))
                .isInstanceOf(RefreshTokenException.class)
                .satisfies(ex -> assertThat(((RefreshTokenException) ex).reason())
                        .isEqualTo(RefreshTokenException.Reason.NOT_FOUND));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static Claims parseClaims(String token, SecretKey key, Instant now) {
        return Jwts.parser()
                .verifyWith(key)
                .clock(() -> Date.from(now))
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // ── stubs ─────────────────────────────────────────────────────────────────

    static class FixedGrantStore implements RefreshTokenStore {
        private final TokenGrant grant;

        FixedGrantStore(TokenGrant grant) { this.grant = grant; }

        @Override public TokenGrant rotate(String rawToken) { return grant; }
        @Override public TokenGrant issue(UUID identityId, UUID familyId) { throw new UnsupportedOperationException(); }
        @Override public void revokeFamily(UUID familyId) { throw new UnsupportedOperationException(); }
        @Override public void revokeFamilyByToken(String rawToken) { throw new UnsupportedOperationException(); }
    }

    static class ThrowingStore implements RefreshTokenStore {
        private final RefreshTokenException ex;

        ThrowingStore(RefreshTokenException ex) { this.ex = ex; }

        @Override public TokenGrant rotate(String rawToken) { throw ex; }
        @Override public TokenGrant issue(UUID identityId, UUID familyId) { throw new UnsupportedOperationException(); }
        @Override public void revokeFamily(UUID familyId) { throw new UnsupportedOperationException(); }
        @Override public void revokeFamilyByToken(String rawToken) { throw new UnsupportedOperationException(); }
    }

    static class FixedIdentityStore implements WalletIdentityStore {
        private final Optional<WalletIdentity> result;
        int findByIdCallCount = 0;

        FixedIdentityStore(Optional<WalletIdentity> result) { this.result = result; }

        @Override
        public WalletIdentity upsertOnLogin(CaipAccountId account) { throw new UnsupportedOperationException(); }

        @Override
        public Optional<WalletIdentity> findById(UUID id) {
            findByIdCallCount++;
            return result;
        }
    }
}
