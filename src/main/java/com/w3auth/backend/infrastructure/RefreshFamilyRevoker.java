package com.w3auth.backend.infrastructure;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * Revokes a refresh-token family in its own committed transaction.
 *
 * <p>This exists as a separate Spring bean so that {@code JpaRefreshTokenStore.rotate()}
 * can revoke a family on reuse detection and have the revocation commit even though
 * rotate() is about to throw. If revocation ran inside rotate()'s own transaction,
 * the exception would roll the revocation back — the family would remain live after a
 * theft signal, which is the exact outcome we must prevent.
 *
 * <p>REQUIRES_NEW suspends the caller's transaction, commits the revocation in its own
 * transaction, then resumes. The caller's rollback (from the throw) cannot undo a
 * transaction that has already committed.
 */
@Component
class RefreshFamilyRevoker {

    private final RefreshTokenRepository repository;
    private final Clock clock;

    RefreshFamilyRevoker(RefreshTokenRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void revokeFamily(UUID familyId) {
        Instant now = clock.instant();
        repository.revokeFamily(familyId, now);
    }
}
