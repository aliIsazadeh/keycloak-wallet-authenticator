package com.w3auth.backend.infrastructure;

import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import com.w3auth.backend.identity.WalletIdentity;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@link JpaWalletIdentityStore} against a real PostgreSQL
 * instance. The {@code @DataJpaTest} slice includes {@code FlywayAutoConfiguration},
 * so V2__wallet_identity.sql runs before any test. Each test rolls back via the
 * outer {@code @Transactional} provided by {@code @DataJpaTest}.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
class JpaWalletIdentityStoreTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    // Same address on mainnet and Polygon — must produce exactly one identity row
    private static final String ADDRESS = "0xabc1234567890abc1234567890abc12345678901";
    private static final CaipAccountId MAINNET =
            CaipAccountId.of(Namespace.EIP155, "1", ADDRESS);
    private static final CaipAccountId POLYGON =
            CaipAccountId.of(Namespace.EIP155, "137", ADDRESS);

    private static final Instant T0 = Instant.parse("2026-06-19T10:00:00Z");
    private static final Instant T1 = Instant.parse("2026-06-19T10:01:00Z");

    @Autowired WalletIdentityRepository repository;
    @Autowired EntityManager entityManager;

    // Manually instantiated — @DataJpaTest doesn't scan @Component beans;
    // @Transactional on upsertOnLogin is a no-op here since the outer test
    // transaction is already active.
    private JpaWalletIdentityStore store;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
        store = new JpaWalletIdentityStore(repository, entityManager, Clock.fixed(T0, ZoneOffset.UTC));
    }

    @Test
    void upsertOnLogin_newAccount_createsRow() {
        WalletIdentity result = store.upsertOnLogin(MAINNET);

        assertThat(result.id()).isNotNull();
        assertThat(result.identityKey().namespace()).isEqualTo(Namespace.EIP155);
        assertThat(result.identityKey().address()).isEqualTo(ADDRESS);
        assertThat(result.status()).isEqualTo("active");
        assertThat(result.createdAt()).isEqualTo(T0);
        assertThat(result.lastLoginAt()).isEqualTo(T0);
        assertThat(repository.count()).isEqualTo(1L);
    }

    @Test
    void upsertOnLogin_secondLogin_updatesLastLoginAtPreservesCreatedAt() {
        store.upsertOnLogin(MAINNET);

        // Second upsert 60 seconds later
        JpaWalletIdentityStore laterStore =
                new JpaWalletIdentityStore(repository, entityManager, Clock.fixed(T1, ZoneOffset.UTC));
        WalletIdentity second = laterStore.upsertOnLogin(MAINNET);

        assertThat(repository.count()).isEqualTo(1L);
        assertThat(second.createdAt()).isEqualTo(T0);       // never changes
        assertThat(second.lastLoginAt()).isEqualTo(T1);     // updated
    }

    @Test
    void upsertOnLogin_differentChainId_sameIdentityRow() {
        // chainId is session context, not identity key — both accounts share the same address
        store.upsertOnLogin(MAINNET);
        store.upsertOnLogin(POLYGON);

        assertThat(repository.count()).isEqualTo(1L);
    }
}
