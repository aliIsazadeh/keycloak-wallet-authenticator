package com.w3auth.backend.usecase;

import com.w3auth.backend.challenge.Challenge;
import com.w3auth.backend.challenge.ChallengePolicy;
import com.w3auth.backend.challenge.ChallengeStore;
import com.w3auth.backend.challenge.SiweMessageFactory;
import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import com.w3auth.backend.identity.WalletIdentity;
import com.w3auth.backend.identity.WalletIdentityStore;
import com.w3auth.backend.session.JwtPolicy;
import com.w3auth.backend.session.JwtService;
import com.w3auth.backend.verification.SignatureVerifier;
import com.w3auth.backend.verification.VerificationException;
import com.w3auth.backend.verification.VerifiedIdentity;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VerifyAndAuthenticateTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-06-15T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);

    private static final String ADDRESS = "0xabc1234567890abc1234567890abc12345678901";
    private static final String CHAIN_ID = "1";
    private static final String NONCE = "testNonce123abc";

    private static final CaipAccountId ACCOUNT = CaipAccountId.of(Namespace.EIP155, CHAIN_ID, ADDRESS);
    private static final ChallengePolicy POLICY = new ChallengePolicy(
            "example.com", "https://example.com/login", Duration.ofMinutes(5));

    private static final SecretKey SIGNING_KEY =
            Keys.hmacShaKeyFor(Base64.getDecoder().decode("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="));
    private static final Duration JWT_TTL = Duration.ofMinutes(10);
    private static final JwtService JWT_SERVICE =
            new JwtService(new JwtPolicy(SIGNING_KEY, JWT_TTL, "wallet-auth"));

    private final InMemoryChallengeStore store = new InMemoryChallengeStore();
    private final InMemoryWalletIdentityStore identityStore = new InMemoryWalletIdentityStore();

    // ── helpers ───────────────────────────────────────────────────────────────

    private Challenge challenge(CaipAccountId account, String nonce, String domain, String uri) {
        return new Challenge(account, nonce, domain, uri, FIXED_NOW, FIXED_NOW.plus(Duration.ofMinutes(5)));
    }

    private Challenge challengeWithTimestamps(String nonce, Instant issuedAt, Instant expiresAt) {
        return new Challenge(ACCOUNT, nonce, POLICY.domain(), POLICY.uri(), issuedAt, expiresAt);
    }

    private Challenge defaultChallenge() {
        return challenge(ACCOUNT, NONCE, POLICY.domain(), POLICY.uri());
    }

    private VerifyAndAuthenticate useCase(SignatureVerifier verifier) {
        return new VerifyAndAuthenticate(store, POLICY, verifier, identityStore, JWT_SERVICE, FIXED_CLOCK);
    }

    /** Verifier stub that always returns the given address without inspecting the request. */
    private static SignatureVerifier returning(String address) {
        return request -> new VerifiedIdentity(address);
    }

    // ── happy path ────────────────────────────────────────────────────────────

    @Test
    void execute_happyPath_returnsAuthResultWithToken() throws VerificationException {
        Challenge c = defaultChallenge();
        store.store(c);

        AuthResult result = useCase(returning(ADDRESS))
                .execute(SiweMessageFactory.create(c), "dummy-sig");

        assertThat(result.token()).isNotBlank();
        assertThat(result.expiresAt()).isEqualTo(FIXED_NOW.plus(JWT_TTL));
    }

    @Test
    void execute_happyPath_tokenSubIsCAIP10String() throws VerificationException {
        Challenge c = defaultChallenge();
        store.store(c);

        AuthResult result = useCase(returning(ADDRESS))
                .execute(SiweMessageFactory.create(c), "dummy-sig");

        Claims claims = Jwts.parser()
                .verifyWith(SIGNING_KEY)
                .clock(() -> Date.from(FIXED_NOW))
                .build()
                .parseSignedClaims(result.token())
                .getPayload();

        assertThat(claims.getSubject())
                .isEqualTo(CaipAccountId.of(Namespace.EIP155, CHAIN_ID, ADDRESS).toString());
    }

    @Test
    void execute_happyPath_upsertsIdentity() throws VerificationException {
        Challenge c = defaultChallenge();
        store.store(c);

        useCase(returning(ADDRESS)).execute(SiweMessageFactory.create(c), "dummy-sig");

        assertThat(identityStore.upserted)
                .containsExactly(CaipAccountId.of(Namespace.EIP155, CHAIN_ID, ADDRESS));
    }

    // ── nonce failures ────────────────────────────────────────────────────────

    @Test
    void execute_nonceNotInStore_throwsVerificationException() {
        String message = SiweMessageFactory.create(defaultChallenge());

        assertThatThrownBy(() -> useCase(returning(ADDRESS)).execute(message, "sig"))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("nonce missing");
    }

    @Test
    void execute_reusedNonce_secondCallThrows() throws VerificationException {
        Challenge c = defaultChallenge();
        store.store(c);
        String message = SiweMessageFactory.create(c);
        VerifyAndAuthenticate uc = useCase(returning(ADDRESS));

        uc.execute(message, "sig"); // first call — consumes the nonce

        assertThatThrownBy(() -> uc.execute(message, "sig"))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("nonce missing");
    }

    // ── field validation failures ─────────────────────────────────────────────

    @Test
    void execute_wrongDomain_throwsVerificationException() {
        store.store(defaultChallenge());

        String evilMessage = SiweMessageFactory.create(
                challenge(ACCOUNT, NONCE, "evil.com", POLICY.uri()));

        assertThatThrownBy(() -> useCase(returning(ADDRESS)).execute(evilMessage, "sig"))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("domain mismatch");
    }

    @Test
    void execute_wrongChainId_throwsVerificationException() {
        store.store(defaultChallenge());

        CaipAccountId polygonAccount = CaipAccountId.of(Namespace.EIP155, "137", ADDRESS);
        String wrongChainMessage = SiweMessageFactory.create(
                challenge(polygonAccount, NONCE, POLICY.domain(), POLICY.uri()));

        assertThatThrownBy(() -> useCase(returning(ADDRESS)).execute(wrongChainMessage, "sig"))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("chainId mismatch");
    }

    @Test
    void execute_wrongUri_throwsVerificationException() {
        store.store(defaultChallenge());

        String wrongUriMessage = SiweMessageFactory.create(
                challenge(ACCOUNT, NONCE, POLICY.domain(), "https://evil.com/login"));

        assertThatThrownBy(() -> useCase(returning(ADDRESS)).execute(wrongUriMessage, "sig"))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("uri mismatch");
    }

    @Test
    void execute_wrongVersion_throwsVerificationException() {
        Challenge c = defaultChallenge();
        store.store(c);
        String wrongVersionMessage = SiweMessageFactory.create(c).replace("Version: 1", "Version: 2");

        assertThatThrownBy(() -> useCase(returning(ADDRESS)).execute(wrongVersionMessage, "sig"))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("unsupported SIWE version");
    }

    // ── timestamp failures ────────────────────────────────────────────────────

    @Test
    void execute_messageExpired_throws() {
        store.store(defaultChallenge());

        Instant pastIssuedAt = FIXED_NOW.minus(Duration.ofMinutes(10));
        Instant pastExpiresAt = FIXED_NOW.minus(Duration.ofMinutes(5));
        String expiredMessage = SiweMessageFactory.create(
                challengeWithTimestamps(NONCE, pastIssuedAt, pastExpiresAt));

        assertThatThrownBy(() -> useCase(returning(ADDRESS)).execute(expiredMessage, "sig"))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void execute_issuedAtInFuture_throws() {
        store.store(defaultChallenge());

        Instant futureIssuedAt = FIXED_NOW.plus(Duration.ofMinutes(10));
        Instant futureExpiresAt = FIXED_NOW.plus(Duration.ofMinutes(15));
        String futureMessage = SiweMessageFactory.create(
                challengeWithTimestamps(NONCE, futureIssuedAt, futureExpiresAt));

        assertThatThrownBy(() -> useCase(returning(ADDRESS)).execute(futureMessage, "sig"))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("future");
    }

    // ── signer mismatch ───────────────────────────────────────────────────────

    @Test
    void execute_signerMismatch_throwsVerificationException() {
        Challenge c = defaultChallenge();
        store.store(c);

        String otherAddress = "0x1111111111111111111111111111111111111111";

        assertThatThrownBy(() -> useCase(returning(otherAddress))
                .execute(SiweMessageFactory.create(c), "sig"))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("signer mismatch");
    }

    // ── in-memory stubs ───────────────────────────────────────────────────────

    static class InMemoryWalletIdentityStore implements WalletIdentityStore {
        final List<CaipAccountId> upserted = new ArrayList<>();

        @Override
        public WalletIdentity upsertOnLogin(CaipAccountId account) {
            upserted.add(account);
            return new WalletIdentity(UUID.randomUUID(), account.identityKey(), "active",
                    Instant.now(), Instant.now());
        }
    }

    static class InMemoryChallengeStore implements ChallengeStore {
        private final Map<String, Challenge> stored = new HashMap<>();

        @Override
        public void store(Challenge challenge) {
            stored.put(challenge.nonce(), challenge);
        }

        @Override
        public Optional<Challenge> consume(String nonce) {
            return Optional.ofNullable(stored.remove(nonce));
        }
    }
}
