package com.w3auth.backend.usecase;

import com.w3auth.backend.identity.WalletIdentity;
import com.w3auth.backend.identity.WalletIdentityStore;
import com.w3auth.backend.session.JwtService;
import com.w3auth.backend.session.RefreshTokenException;
import com.w3auth.backend.session.RefreshTokenStore;
import com.w3auth.backend.session.TokenGrant;

import java.time.Clock;
import java.time.Instant;

/**
 * Rotates a refresh token and mints a fresh access JWT.
 *
 * <p>On success the caller receives a new access token (identical in shape to
 * what {@code /verify} produces for the same wallet) and a new refresh token that
 * replaces the one just consumed. ALL failure modes surface as
 * {@link RefreshTokenException} and are mapped to a uniform, undifferentiated 401
 * at the edge — no internal reason is ever revealed to the client.
 *
 * <p>No Spring annotations — {@code usecase} is a core package. Wiring to Spring
 * happens in {@code infrastructure.config}.
 */
public class RefreshSession {

    private final RefreshTokenStore refreshTokenStore;
    private final WalletIdentityStore walletIdentityStore;
    private final JwtService jwtService;
    private final Clock clock;

    public RefreshSession(RefreshTokenStore refreshTokenStore,
                          WalletIdentityStore walletIdentityStore,
                          JwtService jwtService,
                          Clock clock) {
        this.refreshTokenStore = refreshTokenStore;
        this.walletIdentityStore = walletIdentityStore;
        this.jwtService = jwtService;
        this.clock = clock;
    }

    /**
     * Rotates {@code rawRefreshToken} and returns a fresh token pair.
     *
     * @param rawRefreshToken the opaque refresh token previously given to the client
     * @return the new access token, new refresh token, and access-token expiry
     * @throws RefreshTokenException for all failure cases (unknown, expired, revoked,
     *         reuse detected, lost race, identity missing) — all map to the same 401
     */
    public RefreshResult execute(String rawRefreshToken) {
        // Step 1: rotate — all token validation happens here; propagate any exception unchanged
        TokenGrant grant = refreshTokenStore.rotate(rawRefreshToken);

        // Step 2: resolve the identity the rotated row belongs to
        WalletIdentity identity = walletIdentityStore.findById(grant.token().identityId())
                .orElseThrow(() -> new RefreshTokenException(
                        RefreshTokenException.Reason.NOT_FOUND,
                        "identity not found for rotated token"));

        // Step 3: mint access JWT — sub is identical to what /verify produces for this wallet
        Instant issuedAt = clock.instant();
        String accessToken = jwtService.issue(identity.identityKey(), issuedAt);
        Instant expiresAt = issuedAt.plus(jwtService.ttl());

        return new RefreshResult(accessToken, grant.rawToken(), expiresAt);
    }
}
