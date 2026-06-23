package com.w3auth.backend.usecase;

import com.w3auth.backend.session.RefreshTokenStore;

/**
 * Revokes the refresh-token family associated with the given raw token.
 * Idempotent: presenting an already-revoked or unknown token is a silent no-op.
 * Never signals token validity to the caller — no exception path exists.
 */
public class Logout {

    private final RefreshTokenStore refreshTokenStore;

    public Logout(RefreshTokenStore refreshTokenStore) {
        this.refreshTokenStore = refreshTokenStore;
    }

    public void execute(String rawRefreshToken) {
        refreshTokenStore.revokeFamilyByToken(rawRefreshToken);
    }
}
