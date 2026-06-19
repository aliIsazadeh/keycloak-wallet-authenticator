package com.w3auth.backend.infrastructure;

import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import com.w3auth.backend.identity.WalletIdentity;
import com.w3auth.backend.identity.WalletIdentityStore;
import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

@Component
public class JpaWalletIdentityStore implements WalletIdentityStore {

    private final WalletIdentityRepository repository;
    private final EntityManager entityManager;
    private final Clock clock;

    public JpaWalletIdentityStore(WalletIdentityRepository repository,
                                  EntityManager entityManager,
                                  Clock clock) {
        this.repository = repository;
        this.entityManager = entityManager;
        this.clock = clock;
    }

    @Override
    @Transactional
    public WalletIdentity upsertOnLogin(CaipAccountId account) {
        String namespace = account.namespace().value();
        String address   = account.address();
        // OffsetDateTime maps cleanly to PostgreSQL TIMESTAMPTZ via JDBC 42.x
        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);

        entityManager.createNativeQuery("""
                INSERT INTO wallet_identity (id, namespace, address, status, created_at, last_login_at)
                VALUES (gen_random_uuid(), :namespace, :address, 'active', :now, :now)
                ON CONFLICT (namespace, address) DO UPDATE
                SET last_login_at = :now
                """)
                .setParameter("namespace", namespace)
                .setParameter("address", address)
                .setParameter("now", now)
                .executeUpdate();

        // flush so the native INSERT is visible within this transaction, then clear
        // the L1 cache so the follow-up SELECT goes to the DB (not stale cache state)
        entityManager.flush();
        entityManager.clear();

        WalletIdentityEntity entity = repository.findByNamespaceAndAddress(namespace, address)
                .orElseThrow(() -> new IllegalStateException(
                        "wallet_identity row missing after upsert for " + namespace + ":" + address));

        return toModel(entity);
    }

    static WalletIdentity toModel(WalletIdentityEntity entity) {
        CaipAccountId.IdentityKey key = new CaipAccountId.IdentityKey(
                Namespace.fromString(entity.getNamespace()), entity.getAddress());
        return new WalletIdentity(entity.getId(), key, entity.getStatus(),
                entity.getCreatedAt(), entity.getLastLoginAt());
    }
}
