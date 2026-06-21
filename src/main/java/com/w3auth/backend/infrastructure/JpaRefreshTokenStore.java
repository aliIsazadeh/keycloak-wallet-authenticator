package com.w3auth.backend.infrastructure;

import com.w3auth.backend.session.RefreshToken;
import com.w3auth.backend.session.RefreshTokenException;
import com.w3auth.backend.session.RefreshTokenPolicy;
import com.w3auth.backend.session.RefreshTokenStore;
import com.w3auth.backend.session.TokenGrant;
import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Component
public class JpaRefreshTokenStore implements RefreshTokenStore {

    // 32 bytes = 256 bits of entropy. SHA-256 is appropriate here (not bcrypt) because
    // the token is already high-entropy random — brute force is infeasible regardless of
    // hashing speed. Bcrypt's cost factor only defends low-entropy secrets (passwords).
    private static final int TOKEN_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final RefreshTokenRepository repository;
    private final EntityManager entityManager;
    private final RefreshTokenPolicy policy;
    private final RefreshFamilyRevoker familyRevoker;
    private final Clock clock;

    public JpaRefreshTokenStore(RefreshTokenRepository repository,
                                EntityManager entityManager,
                                RefreshTokenPolicy policy,
                                RefreshFamilyRevoker familyRevoker,
                                Clock clock) {
        this.repository = repository;
        this.entityManager = entityManager;
        this.policy = policy;
        this.familyRevoker = familyRevoker;
        this.clock = clock;
    }

    @Override
    @Transactional
    public TokenGrant issue(UUID identityId, UUID familyId) {
        Instant now = clock.instant();
        String raw = generateRaw();
        String hash = sha256Hex(raw);
        UUID id = UUID.randomUUID();
        Instant expiresAt = now.plus(policy.ttl());

        RefreshTokenEntity entity = new RefreshTokenEntity(id, familyId, identityId, hash, expiresAt, now);
        entityManager.persist(entity);

        return new TokenGrant(raw, toModel(entity));
    }

    // Plain @Transactional — READ_COMMITTED (Postgres default). No isolation override.
    //
    // Reuse is classified at READ time, not at UPDATE time:
    //
    //   If replaced_by is already set when the row is first loaded, this transaction
    //   started AFTER the rotation that set it committed. There was no overlap. The
    //   presenter is showing a spent token — whether they are a thief or a client that
    //   retried after its first rotation already completed, the store cannot distinguish
    //   them and must not try. revokeFamily() is called (via REQUIRES_NEW so the revoke
    //   commits even though this transaction is about to throw and roll back), then throw.
    //
    //   If replaced_by is NULL at read time, the transaction genuinely overlapped the
    //   winner's (or is the only caller). We mint a replacement, INSERT it, then run the
    //   guarded claim UPDATE. Under READ_COMMITTED, Postgres serialises concurrent UPDATEs
    //   to the same row via row-level locking: the loser's UPDATE waits, then executes
    //   after the winner commits, at which point the WHERE (replaced_by IS NULL) fails →
    //   0 rows. 0 rows = benign race. Throw without revoking; the transaction rolls back,
    //   undoing the INSERT so no orphan row persists.
    //
    // Load-bearing rule: a 0-row UPDATE result is NEVER classified as reuse.
    // Do NOT re-read the row after a 0-row update to reclassify it — that re-read is the
    // bug this design exists to avoid: it would let a benign concurrent loser revoke the
    // winner's brand-new token.
    //
    // INSERT before UPDATE: replaced_by is a self-FK, so the target row must exist
    // before the UPDATE can point at it.
    @Override
    @Transactional
    public TokenGrant rotate(String rawToken) {
        String hash = sha256Hex(rawToken);
        Instant now = clock.instant();

        RefreshTokenEntity old = repository.findByTokenHash(hash)
                .orElseThrow(() -> new RefreshTokenException("refresh token not found"));

        if (old.getExpiresAt().isBefore(now)) {
            throw new RefreshTokenException("refresh token expired");
        }
        if (old.getRevokedAt() != null) {
            throw new RefreshTokenException("refresh token family is revoked");
        }

        // Reuse at read time: replaced_by already set means this transaction started
        // after a prior rotation committed. No overlap with the winner. Revoke and throw.
        if (old.getReplacedBy() != null) {
            familyRevoker.revokeFamily(old.getFamilyId());
            throw new RefreshTokenException("refresh token reuse detected — family revoked");
        }

        // Row is live. Mint a replacement in the same family.
        UUID newId = UUID.randomUUID();
        String newRaw = generateRaw();
        String newHash = sha256Hex(newRaw);
        Instant newExpiry = now.plus(policy.ttl());

        RefreshTokenEntity newEntity = new RefreshTokenEntity(
                newId, old.getFamilyId(), old.getIdentityId(), newHash, newExpiry, now);
        entityManager.persist(newEntity);
        // Flush INSERT before the UPDATE so the self-FK target exists at statement time.
        entityManager.flush();

        // Guarded claim: exactly one concurrent rotate() wins.
        // Under READ_COMMITTED, Postgres row-level locking serialises concurrent UPDATEs:
        //   winner  → 1 row updated, commits normally
        //   loser   → UPDATE waits on the row lock; after winner commits, WHERE clause
        //             (replaced_by IS NULL) no longer holds → 0 rows → benign race
        // 0 rows is not reuse. Throw and let the transaction roll back (undoes the INSERT).
        int claimed = repository.claimForRotation(old.getId(), newId);
        if (claimed == 0) {
            throw new RefreshTokenException("refresh token already rotated");
        }

        return new TokenGrant(newRaw, toModel(newEntity));
    }

    @Override
    @Transactional
    public void revokeFamily(UUID familyId) {
        repository.revokeFamily(familyId, clock.instant());
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static String generateRaw() {
        byte[] bytes = new byte[TOKEN_BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static RefreshToken toModel(RefreshTokenEntity e) {
        return new RefreshToken(
                e.getId(), e.getFamilyId(), e.getIdentityId(),
                e.getTokenHash(), e.getReplacedBy(),
                e.getExpiresAt(), e.getRevokedAt(), e.getCreatedAt());
    }
}
