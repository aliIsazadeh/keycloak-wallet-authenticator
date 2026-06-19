package com.w3auth.backend.identity;

/**
 * Port for persisting wallet identity. Implemented in {@code infrastructure}
 * by {@code JpaWalletIdentityStore}; kept here so core packages can depend on
 * it without importing Spring or JPA.
 */
public interface WalletIdentityStore {

    /**
     * Atomically inserts the identity on first login, or updates
     * {@code last_login_at} on subsequent logins. Race-safe: uses
     * {@code INSERT ... ON CONFLICT DO UPDATE} under the hood.
     *
     * @return the current row state after the upsert
     */
    WalletIdentity upsertOnLogin(CaipAccountId account);
}
