package com.w3auth.backend.infrastructure;

import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import com.w3auth.backend.identity.WalletIdentityStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Clock;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Concurrency test for {@link JpaWalletIdentityStore#upsertOnLogin}. Uses the real
 * Spring-managed bean (so the {@code @Transactional} proxy is active) and a real
 * PostgreSQL instance. Every thread goes through the full upsert → flush → clear →
 * findByNamespaceAndAddress sequence in its own committed transaction.
 *
 * <p>{@code @Transactional(NOT_SUPPORTED)} on the test method tells Spring Test's
 * transaction listener not to start an outer transaction for this test's lifecycle.
 * That means:
 * <ul>
 *   <li>{@code @BeforeEach deleteAll()} commits its own transaction (clean slate).</li>
 *   <li>Each thread's {@code store.upsertOnLogin()} gets its own committed transaction
 *       (REQUIRED propagation, no parent to join).</li>
 *   <li>{@code repository.count()} reads committed rows in its own read-only transaction.</li>
 * </ul>
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
@Import(JpaWalletIdentityStore.class)
class WalletIdentityConcurrencyTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @TestConfiguration
    static class Config {
        @Bean
        Clock clock() {
            return Clock.systemUTC();
        }
    }

    private static final CaipAccountId ACCOUNT =
            CaipAccountId.of(Namespace.EIP155, "1", "0xabc1234567890abc1234567890abc12345678901");

    // Spring-managed: @Transactional on upsertOnLogin is active via AOP proxy
    @Autowired
    WalletIdentityStore store;

    @Autowired
    WalletIdentityRepository repository;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    @Test
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void upsertOnLogin_concurrent_exactlyOneRow() throws Exception {
        int threadCount = 8;
        CountDownLatch startGun = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        AtomicReference<Throwable> firstError = new AtomicReference<>();

        for (int i = 0; i < threadCount; i++) {
            Thread.ofVirtual().start(() -> {
                try {
                    startGun.await();
                    store.upsertOnLogin(ACCOUNT);
                } catch (Throwable t) {
                    firstError.compareAndSet(null, t);
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startGun.countDown();
        assertThat(doneLatch.await(10, TimeUnit.SECONDS)).isTrue();

        if (firstError.get() != null) {
            throw new AssertionError("upsertOnLogin threw on a concurrent thread", firstError.get());
        }

        assertThat(repository.count()).isEqualTo(1L);
    }
}
