package com.w3auth.backend.infrastructure;

import com.w3auth.backend.usecase.AuthEventStore;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * JPA implementation of {@link AuthEventStore}. Runs in a new transaction
 * (propagation = REQUIRES_NEW) to guarantee that audit events are recorded
 * even if the calling usecase's transaction rolls back (e.g. login failure).
 */
@Component
public class JpaAuthEventStore implements AuthEventStore {

    private final AuthEventJpaRepository repository;

    public JpaAuthEventStore(AuthEventJpaRepository repository) {
        this.repository = repository;
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logEvent(UUID identityId, String eventType, String ipAddress, String userAgent, String details, Instant timestamp) {
        AuthEventEntity entity = new AuthEventEntity(
                UUID.randomUUID(),
                identityId,
                eventType,
                ipAddress,
                userAgent,
                details,
                timestamp
        );
        repository.save(entity);
    }
}
