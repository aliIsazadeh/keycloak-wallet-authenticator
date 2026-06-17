package com.w3auth.backend.challenge;

import com.w3auth.backend.identity.CaipAccountId;

import java.time.Instant;
import java.util.Objects;

/**
 * A challenge issued to a claimed account: the nonce and message fields the
 * server is authoritative on, to be validated against the SIWE message
 * presented at verification time (M1).
 */
public record Challenge(
        CaipAccountId account,
        String nonce,
        String domain,
        String uri,
        Instant issuedAt,
        Instant expiresAt) {

    public Challenge {
        Objects.requireNonNull(account, "account must not be null");
        if (nonce == null || nonce.isBlank()) {
            throw new IllegalArgumentException("nonce must not be blank");
        }
        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException("domain must not be blank");
        }
        if (uri == null || uri.isBlank()) {
            throw new IllegalArgumentException("uri must not be blank");
        }
        Objects.requireNonNull(issuedAt, "issuedAt must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        if (!expiresAt.isAfter(issuedAt)) {
            throw new IllegalArgumentException("expiresAt must be after issuedAt");
        }
    }

    /**
     * The CAIP-2 chain reference (chain id) this challenge was issued for —
     * session/auth context, derived from {@link #account()}.
     */
    public String chainId() {
        return account.reference();
    }
}
