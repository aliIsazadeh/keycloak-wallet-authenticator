package com.w3auth.backend.infrastructure;

import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import com.w3auth.backend.identity.WalletIdentity;
import com.w3auth.backend.identity.WalletIdentityStore;
import com.w3auth.backend.session.RefreshTokenPolicy;
import com.w3auth.backend.session.RefreshTokenStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Concurrency test for the atomic-claim guarantee in
 * {@link RefreshTokenRepository#claimForRotation}.
 *
 * <h3>Why this tests claimForRotation directly, not the full rotate()</h3>
 * <p>The full {@code rotate()} is a SELECT → INSERT → UPDATE → COMMIT pipeline. Under
 * virtual-thread scheduling, one thread can complete the entire pipeline and commit before
 * the other threads even issue their first SELECT (confirmed by SQL log from a prior attempt:
 * winner's SELECT + INSERT + UPDATE committed in sequence, then 7 sequential reads all saw
 * {@code replaced_by} already set). Those 7 threads correctly classified the row as
 * sequential reuse — the store behaved correctly, but the test's premise — 8 threads with
 * genuinely overlapping pipeline executions — was not achieved. Forcing it would require
 * moving the transaction boundary out of the store into the test harness (PlatformTransaction-
 * Manager gating), which was rejected: it gives a false pass on the store's own
 * rollback/orphan-prevention guarantee.
 *
 * <p>A single SQL UPDATE, unlike a multi-step pipeline, genuinely overlaps at the DB:
 * 8 concurrent UPDATEs to the same row serialize via Postgres row-level locking exactly as
 * 8 concurrent {@code INSERT … ON CONFLICT DO UPDATE} statements do in
 * {@code WalletIdentityConcurrencyTest}. That is what this test exercises.
 *
 * <p>The property "a benign concurrent loser in rotate() fails without revoking the family"
 * is covered by reasoning from the code: the 0-row branch in
 * {@link JpaRefreshTokenStore#rotate} throws {@code RefreshTokenException} with no call to
 * {@code revokeFamily()}. This test proves that {@code claimForRotation} itself has no
 * revocation side-effect, completing the argument.
 *
 * <h3>Why the pool is sized to THREAD_COUNT</h3>
 * <p>All 8 UPDATE statements must be in-flight simultaneously. Without N connections,
 * threads serialize at the pool before reaching Postgres and there is no row-level contention
 * to test.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
@Import({JpaRefreshTokenStore.class, RefreshFamilyRevoker.class, JpaWalletIdentityStore.class})
class RefreshTokenConcurrencyTest {

    private static final int THREAD_COUNT = 8;

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void configurePool(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.hikari.minimum-idle",      () -> THREAD_COUNT);
        registry.add("spring.datasource.hikari.maximum-pool-size", () -> THREAD_COUNT + 2);
    }

    @TestConfiguration
    static class Config {
        @Bean Clock clock()               { return Clock.systemUTC(); }
        @Bean RefreshTokenPolicy policy() { return new RefreshTokenPolicy(Duration.ofDays(30)); }
    }

    private static final CaipAccountId TEST_ACCOUNT =
            CaipAccountId.of(Namespace.EIP155, "1", "0xdef1234567890def1234567890def12345678902");

    @Autowired RefreshTokenStore        store;
    @Autowired WalletIdentityStore      identityStore;
    @Autowired WalletIdentityRepository identityRepository;
    @Autowired RefreshTokenRepository   refreshTokenRepository;
    @Autowired PlatformTransactionManager txManager;

    private UUID identityId;

    @BeforeEach
    void setUp() {
        refreshTokenRepository.deleteAll();
        identityRepository.deleteAll();
        WalletIdentity identity = identityStore.upsertOnLogin(TEST_ACCOUNT);
        identityId = identity.id();
    }

    @Test
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void claimForRotation_concurrent_exactlyOneWinner_neverRevokes() throws Exception {
        UUID familyId = UUID.randomUUID();

        // The single live token that all threads will race to claim via guarded UPDATE.
        UUID oldId = store.issue(identityId, familyId).token().id();

        // Pre-insert THREAD_COUNT candidate rows to satisfy the replaced_by self-FK.
        // Only the single winning UPDATE (1 row) triggers the FK check; the 7 losers
        // produce 0 rows and never touch the FK. Each candidate uses a distinct familyId
        // so it does not contaminate the revocation check for familyId below.
        List<UUID> candidateIds = new ArrayList<>();
        for (int i = 0; i < THREAD_COUNT; i++) {
            candidateIds.add(store.issue(identityId, UUID.randomUUID()).token().id());
        }

        // Each thread needs its own committed transaction for the standalone claimForRotation
        // call. claimForRotation carries no @Transactional (it joins rotate()'s transaction
        // in production); the boundary for this test-only invocation belongs in the test.
        TransactionTemplate template = new TransactionTemplate(txManager);

        CountDownLatch startGun  = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(THREAD_COUNT);
        AtomicInteger  winners   = new AtomicInteger();
        AtomicInteger  losers    = new AtomicInteger();
        List<Throwable> errors   = new CopyOnWriteArrayList<>();

        for (int i = 0; i < THREAD_COUNT; i++) {
            final UUID newId = candidateIds.get(i);
            Thread.ofVirtual().start(() -> {
                try {
                    startGun.await();
                    Integer rows = template.execute(
                            status -> refreshTokenRepository.claimForRotation(oldId, newId));
                    if (rows != null && rows == 1) winners.incrementAndGet();
                    else                           losers.incrementAndGet();
                } catch (Throwable t) {
                    errors.add(t);
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startGun.countDown();
        assertThat(doneLatch.await(15, TimeUnit.SECONDS)).isTrue();

        assertThat(errors).isEmpty();
        assertThat(winners.get())
                .as("exactly one thread wins the guarded UPDATE")
                .isEqualTo(1);
        assertThat(losers.get())
                .as("all other threads get 0 rows — WHERE replaced_by IS NULL fails after winner commits")
                .isEqualTo(THREAD_COUNT - 1);

        // claimForRotation contains no revocation call; this test confirms the atomic-claim
        // primitive is side-effect-free. That rotate()'s 0-row branch calls only
        // claimForRotation (and therefore cannot revoke) is verified by reading the method,
        // not by this test.
        long revokedCount = refreshTokenRepository.findAll().stream()
                .filter(e -> e.getFamilyId().equals(familyId))
                .filter(e -> e.getRevokedAt() != null)
                .count();
        assertThat(revokedCount)
                .as("claimForRotation has no revocation side-effect")
                .isEqualTo(0);
    }
}
