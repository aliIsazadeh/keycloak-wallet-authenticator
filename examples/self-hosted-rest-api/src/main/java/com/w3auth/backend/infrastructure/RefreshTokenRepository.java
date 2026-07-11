package com.w3auth.backend.infrastructure;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, UUID> {

    Optional<RefreshTokenEntity> findByTokenHash(String tokenHash);

    /**
     * Sets revoked_at on all live tokens in the family. Idempotent: already-revoked
     * rows satisfy the WHERE clause's IS NULL guard and are left untouched.
     */
    @Modifying
    @Query(value = """
            UPDATE refresh_token
            SET    revoked_at = :now
            WHERE  family_id  = :familyId
              AND  revoked_at IS NULL
            """, nativeQuery = true)
    void revokeFamily(UUID familyId, Instant now);

    /**
     * Atomically claims the old token for rotation by setting replaced_by.
     *
     * <p>The WHERE predicate is the full liveness check: the row must still be
     * unreplaced, unrevoked, and unexpired at the moment the UPDATE runs.
     * Returns the number of rows updated (0 = lost the race, 1 = won).
     */
    @Modifying
    @Query(value = """
            UPDATE refresh_token
            SET    replaced_by = :newId
            WHERE  id          = :oldId
              AND  replaced_by IS NULL
              AND  revoked_at  IS NULL
              AND  expires_at  > now()
            """, nativeQuery = true)
    int claimForRotation(UUID oldId, UUID newId);

    /**
     * Back-dates a token's expiry to one hour ago. Used in tests to simulate an
     * expired token without requiring a custom clock or negative-TTL policy.
     */
    @Transactional
    @Modifying
    @Query(value = """
            UPDATE refresh_token
            SET    expires_at = now() - interval '1 hour'
            WHERE  token_hash = :hash
            """, nativeQuery = true)
    void expireByHash(String hash);
}
