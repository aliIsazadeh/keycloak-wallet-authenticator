package com.w3auth.backend.infrastructure;

import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import com.w3auth.backend.identity.WalletIdentity;
import com.w3auth.backend.identity.WalletIdentityStore;
import com.w3auth.backend.session.RefreshToken;
import com.w3auth.backend.session.RefreshTokenException;
import com.w3auth.backend.session.RefreshTokenPolicy;
import com.w3auth.backend.session.RefreshTokenStore;
import com.w3auth.backend.session.TokenGrant;
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
import java.time.Duration;
import java.util.UUID;

import static com.w3auth.backend.infrastructure.JpaRefreshTokenStore.sha256Hex;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Integration tests for {@link JpaRefreshTokenStore} against a real PostgreSQL instance.
 *
 * <p>All test methods run with {@code NOT_SUPPORTED} propagation so each store call
 * gets its own committed transaction. This is required because the reuse-detection path
 * calls revokeFamily via {@code REQUIRES_NEW}, which would produce confusing rollback
 * interactions with an outer test transaction.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
@Import({JpaRefreshTokenStore.class, RefreshFamilyRevoker.class, JpaWalletIdentityStore.class})
class JpaRefreshTokenStoreTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @TestConfiguration
    static class Config {
        @Bean
        Clock clock() { return Clock.systemUTC(); }

        @Bean
        RefreshTokenPolicy refreshTokenPolicy() { return new RefreshTokenPolicy(Duration.ofDays(30)); }
    }

    private static final CaipAccountId TEST_ACCOUNT =
            CaipAccountId.of(Namespace.EIP155, "1", "0xabc1234567890abc1234567890abc12345678901");

    @Autowired RefreshTokenStore store;
    @Autowired WalletIdentityStore identityStore;
    @Autowired WalletIdentityRepository identityRepository;
    @Autowired RefreshTokenRepository refreshTokenRepository;

    private UUID identityId;

    // @BeforeEach runs outside any Spring Test transaction when tests are NOT_SUPPORTED.
    // Each repository/store call here starts and commits its own transaction (REQUIRED).
    @BeforeEach
    void setUp() {
        refreshTokenRepository.deleteAll();
        identityRepository.deleteAll();
        WalletIdentity identity = identityStore.upsertOnLogin(TEST_ACCOUNT);
        identityId = identity.id();
    }

    // ── issue ────────────────────────────────────────────────────────────────

    @Test
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void issue_createsLiveRow_withHashedToken() {
        UUID familyId = UUID.randomUUID();
        TokenGrant grant = store.issue(identityId, familyId);

        assertThat(grant.rawToken()).isNotBlank();
        assertThat(grant.token().id()).isNotNull();
        assertThat(grant.token().familyId()).isEqualTo(familyId);
        assertThat(grant.token().identityId()).isEqualTo(identityId);
        assertThat(grant.token().replacedBy()).isNull();
        assertThat(grant.token().revokedAt()).isNull();
        assertThat(grant.token().expiresAt()).isNotNull();

        // Stored hash must be SHA-256(rawToken) — the raw token must not appear in the row
        String expectedHash = sha256Hex(grant.rawToken());
        assertThat(grant.token().tokenHash()).isEqualTo(expectedHash);
        assertThat(grant.token().tokenHash()).doesNotContain(grant.rawToken());
    }

    // ── rotate ───────────────────────────────────────────────────────────────

    @Test
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void rotate_liveToken_returnsNewTokenAndLinksOldRow() {
        UUID familyId = UUID.randomUUID();
        TokenGrant first = store.issue(identityId, familyId);

        TokenGrant second = store.rotate(first.rawToken());

        // New token is different
        assertThat(second.rawToken()).isNotEqualTo(first.rawToken());

        // New row is live in the same family
        RefreshToken newRow = second.token();
        assertThat(newRow.familyId()).isEqualTo(familyId);
        assertThat(newRow.identityId()).isEqualTo(identityId);
        assertThat(newRow.replacedBy()).isNull();
        assertThat(newRow.revokedAt()).isNull();

        // Old row must have replaced_by pointing to the new row's id
        RefreshTokenEntity oldEntity = refreshTokenRepository
                .findByTokenHash(sha256Hex(first.rawToken())).orElseThrow();
        assertThat(oldEntity.getReplacedBy()).isEqualTo(newRow.id());
    }

    @Test
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void rotate_alreadyRotatedToken_revokesEntireFamilyAndThrows() {
        UUID familyId = UUID.randomUUID();
        TokenGrant first = store.issue(identityId, familyId);
        store.rotate(first.rawToken()); // first rotation — first.rawToken is now spent

        // Presenting the already-rotated token is the reuse/theft signal.
        // The second rotate() starts its transaction AFTER the first rotation committed,
        // reads replaced_by != NULL, classifies as reuse, and revokes the family.
        assertThatThrownBy(() -> store.rotate(first.rawToken()))
                .isInstanceOf(RefreshTokenException.class)
                .satisfies(ex -> assertThat(((RefreshTokenException) ex).reason())
                        .isEqualTo(RefreshTokenException.Reason.REUSE_DETECTED));

        // The entire family must be revoked (the REQUIRES_NEW revocation committed)
        refreshTokenRepository.findAll().stream()
                .filter(e -> e.getFamilyId().equals(familyId))
                .forEach(e -> assertThat(e.getRevokedAt())
                        .as("row %s in family should be revoked", e.getId())
                        .isNotNull());
    }

    @Test
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void rotate_afterRevokeFamily_throws() {
        UUID familyId = UUID.randomUUID();
        TokenGrant grant = store.issue(identityId, familyId);
        store.revokeFamily(familyId);

        assertThatThrownBy(() -> store.rotate(grant.rawToken()))
                .isInstanceOf(RefreshTokenException.class)
                .satisfies(ex -> assertThat(((RefreshTokenException) ex).reason())
                        .isEqualTo(RefreshTokenException.Reason.FAMILY_REVOKED));
    }

    @Test
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void rotate_unknownToken_throws() {
        assertThatThrownBy(() -> store.rotate("totally-unknown-token"))
                .isInstanceOf(RefreshTokenException.class)
                .satisfies(ex -> assertThat(((RefreshTokenException) ex).reason())
                        .isEqualTo(RefreshTokenException.Reason.NOT_FOUND));
    }

    @Test
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void rotate_expiredToken_throws() {
        UUID familyId = UUID.randomUUID();
        TokenGrant grant = store.issue(identityId, familyId);
        // Back-date the row so the token is expired at rotate time.
        refreshTokenRepository.expireByHash(sha256Hex(grant.rawToken()));

        assertThatThrownBy(() -> store.rotate(grant.rawToken()))
                .isInstanceOf(RefreshTokenException.class)
                .satisfies(ex -> assertThat(((RefreshTokenException) ex).reason())
                        .isEqualTo(RefreshTokenException.Reason.EXPIRED));
    }
}
