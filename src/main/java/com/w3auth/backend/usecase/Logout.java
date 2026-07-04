package com.w3auth.backend.usecase;

import com.w3auth.backend.session.RefreshTokenStore;

import java.time.Clock;
import java.time.Instant;

/**
 * Revokes the refresh-token family associated with the given raw token.
 * Idempotent: presenting an already-revoked or unknown token is a silent no-op.
 * Never signals token validity to the caller — no exception path exists.
 */
public class Logout {

    private final RefreshTokenStore refreshTokenStore;
    private final Clock clock;
    private final AuthEventStore authEventStore;

    /**
     * Backward-compatible constructor for testing.
     */
    public Logout(RefreshTokenStore refreshTokenStore) {
        this(refreshTokenStore, Clock.systemUTC(), (id, type, ip, ua, details, ts) -> {});
    }

    public Logout(RefreshTokenStore refreshTokenStore, Clock clock, AuthEventStore authEventStore) {
        this.refreshTokenStore = refreshTokenStore;
        this.clock = clock;
        this.authEventStore = authEventStore;
    }

    /**
     * Backward-compatible execute signature.
     */
    public void execute(String rawRefreshToken) {
        execute(rawRefreshToken, null, null);
    }

    public void execute(String rawRefreshToken, String ipAddress, String userAgent) {
        refreshTokenStore.revokeFamilyByToken(rawRefreshToken);
        authEventStore.logEvent(null, "LOGOUT", ipAddress, userAgent, "Token revoked", clock.instant());
    }
}
