package com.w3auth.backend.identity;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * The durable identity record for a wallet: the result of a successful
 * {@code upsertOnLogin}. Immutable core model — no JPA or Spring imports.
 */
public record WalletIdentity(
        UUID id,
        CaipAccountId.IdentityKey identityKey,
        String status,
        Instant createdAt,
        Instant lastLoginAt) {

    public WalletIdentity {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(identityKey, "identityKey");
        if (status == null || status.isBlank()) throw new IllegalArgumentException("status must not be blank");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(lastLoginAt, "lastLoginAt");
    }
}
