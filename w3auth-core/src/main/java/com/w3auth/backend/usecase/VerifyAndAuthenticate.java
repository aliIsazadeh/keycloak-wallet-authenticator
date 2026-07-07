package com.w3auth.backend.usecase;

import com.w3auth.backend.challenge.Challenge;
import com.w3auth.backend.challenge.ChallengePolicy;
import com.w3auth.backend.challenge.ChallengeStore;
import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import com.w3auth.backend.identity.SolanaCluster;
import com.w3auth.backend.identity.WalletIdentity;
import com.w3auth.backend.identity.WalletIdentityStore;
import com.w3auth.backend.session.JwtService;
import com.w3auth.backend.session.RefreshTokenStore;
import com.w3auth.backend.session.TokenGrant;
import com.w3auth.backend.verification.SignatureVerifier;
import com.w3auth.backend.verification.AuthMessage;
import com.w3auth.backend.verification.SiweMessageParser;
import com.w3auth.backend.verification.SiwsMessageParser;
import com.w3auth.backend.verification.VerificationException;
import com.w3auth.backend.verification.VerificationRequest;
import com.w3auth.backend.verification.VerifiedIdentity;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * Orchestrates the full verify flow across namespaces: parse → consume nonce → validate
 * fields → verify signature → check signer → upsert identity → issue access JWT.
 *
 * <p>No Spring annotations — {@code usecase} is a core package. Wiring to
 * Spring happens in {@code config.UseCaseConfiguration}.
 */
public class VerifyAndAuthenticate {

    private final ChallengeStore challengeStore;
    private final ChallengePolicy policy;
    private final SignatureVerifier signatureVerifier;
    private final WalletIdentityStore identityStore;
    private final RefreshTokenStore refreshTokenStore;
    private final JwtService jwtService;
    private final Clock clock;
    private final AuthEventStore authEventStore;

    /**
     * Backward-compatible constructor for testing.
     */
    public VerifyAndAuthenticate(ChallengeStore challengeStore, ChallengePolicy policy,
                                 SignatureVerifier signatureVerifier,
                                 WalletIdentityStore identityStore,
                                 RefreshTokenStore refreshTokenStore,
                                 JwtService jwtService, Clock clock) {
        this(challengeStore, policy, signatureVerifier, identityStore, refreshTokenStore, jwtService, clock,
                (id, type, ip, ua, details, ts) -> {});
    }

    public VerifyAndAuthenticate(ChallengeStore challengeStore, ChallengePolicy policy,
                                 SignatureVerifier signatureVerifier,
                                 WalletIdentityStore identityStore,
                                 RefreshTokenStore refreshTokenStore,
                                 JwtService jwtService, Clock clock,
                                 AuthEventStore authEventStore) {
        this.challengeStore = challengeStore;
        this.policy = policy;
        this.signatureVerifier = signatureVerifier;
        this.identityStore = identityStore;
        this.refreshTokenStore = refreshTokenStore;
        this.jwtService = jwtService;
        this.clock = clock;
        this.authEventStore = authEventStore;
    }

    /**
     * Backward-compatible execute method signature.
     */
    public AuthResult execute(String rawMessage, String signature) throws VerificationException {
        return execute(rawMessage, signature, null, null);
    }

    /**
     * Verifies a signed auth message (SIWE or SIWS) and returns an access JWT for the authenticated wallet.
     *
     * @param rawMessage the plaintext message exactly as presented for signing
     * @param signature  the encoded signature from the wallet
     * @param ipAddress  the client's IP address (for audit logs)
     * @param userAgent  the client's User-Agent string (for audit logs)
     * @return an {@link AuthResult} containing the access token and its expiry
     * @throws VerificationException for any failure: malformed message, nonce
     *         missing/expired/reused, field mismatch, invalid signature, or
     *         signer-address mismatch
     */
    public AuthResult execute(String rawMessage, String signature, String ipAddress, String userAgent) throws VerificationException {
        Instant now = clock.instant();
        try {
            return executeInternal(rawMessage, signature, ipAddress, userAgent, now);
        } catch (Exception e) {
            authEventStore.logEvent(null, "LOGIN_FAILED", ipAddress, userAgent, e.getMessage(), now);
            throw e;
        }
    }

    private AuthResult executeInternal(String rawMessage, String signature, String ipAddress, String userAgent, Instant now) throws VerificationException {
        // Step 1: parse the message dynamically — fail fast before touching the nonce store
        Namespace namespace;
        try {
            namespace = detectNamespace(rawMessage);
        } catch (IllegalArgumentException e) {
            throw new VerificationException("malformed message: " + e.getMessage(), e);
        }

        AuthMessage parsed;
        try {
            parsed = switch (namespace) {
                case EIP155 -> SiweMessageParser.parse(rawMessage);
                case SOLANA -> SiwsMessageParser.parse(rawMessage);
            };
        } catch (IllegalArgumentException e) {
            throw new VerificationException("malformed " + namespace + " message: " + e.getMessage(), e);
        }

        // Step 2: atomically consume the nonce — replay gate, must precede all sig work.
        Challenge challenge = challengeStore.consume(parsed.nonce())
                .orElseThrow(() -> new VerificationException(
                        "nonce missing, expired, or already used"));

        // Step 3: field validation — message must match what the server issued
        validateFields(parsed, challenge);

        // Step 4: signature verification
        VerifiedIdentity verified = signatureVerifier.verify(new VerificationRequest(parsed, rawMessage, signature));

        // Step 5: signer must equal the address the message claims
        boolean matches = (namespace == Namespace.SOLANA)
                ? verified.signerAddress().equals(parsed.address())
                : verified.signerAddress().equalsIgnoreCase(parsed.address());
        if (!matches) {
            throw new VerificationException(
                    "signer mismatch: recovered '" + verified.signerAddress()
                    + "' but message claims '" + parsed.address() + "'");
        }

        // Step 6: upsert wallet identity (first durable write)
        String chainReference = parsed.chainId();
        if (namespace == Namespace.SOLANA) {
            SolanaCluster cluster = SolanaCluster.fromClusterName(parsed.chainId());
            chainReference = cluster.genesisHash();
        }
        CaipAccountId account = CaipAccountId.of(namespace, chainReference, parsed.address());
        WalletIdentity identity = identityStore.upsertOnLogin(account);

        // Step 7: issue access JWT and first refresh token of a new family.
        String token = jwtService.issue(account.identityKey(), now);
        TokenGrant grant = refreshTokenStore.issue(identity.id(), UUID.randomUUID());

        authEventStore.logEvent(identity.id(), "LOGIN_SUCCESS", ipAddress, userAgent, "Account: " + account, now);

        return new AuthResult(token, grant.rawToken(), now.plus(jwtService.ttl()));
    }

    private static Namespace detectNamespace(String rawMessage) {
        if (rawMessage == null) {
            throw new IllegalArgumentException("message must not be null");
        }
        int firstNewLine = rawMessage.indexOf('\n');
        String firstLine = (firstNewLine == -1) ? rawMessage : rawMessage.substring(0, firstNewLine);
        if (firstLine.endsWith("\r")) {
            firstLine = firstLine.substring(0, firstLine.length() - 1);
        }
        if (firstLine.endsWith(" wants you to sign in with your Ethereum account:")) {
            return Namespace.EIP155;
        } else if (firstLine.endsWith(" wants you to sign in with your Solana account:")) {
            return Namespace.SOLANA;
        }
        throw new IllegalArgumentException("Unknown or unsupported authentication message format");
    }

    private void validateFields(AuthMessage parsed, Challenge challenge) throws VerificationException {
        if (!parsed.domain().equals(policy.domain())) {
            throw new VerificationException(
                    "domain mismatch: expected '" + policy.domain() + "', got '" + parsed.domain() + "'");
        }
        if (!parsed.uri().equals(policy.uri())) {
            throw new VerificationException(
                    "uri mismatch: expected '" + policy.uri() + "', got '" + parsed.uri() + "'");
        }
        if (!"1".equals(parsed.version())) {
            String type = (parsed.namespace() == Namespace.SOLANA) ? "SIWS" : "SIWE";
            throw new VerificationException("unsupported " + type + " version: '" + parsed.version() + "'");
        }

        // Security check: nonce must be bound to address and namespace
        if (parsed.namespace() != challenge.account().namespace()) {
            throw new VerificationException("namespace mismatch: expected '" + challenge.account().namespace()
                    + "', got '" + parsed.namespace() + "'");
        }
        boolean addressMatches = (challenge.account().namespace() == Namespace.SOLANA)
                ? parsed.address().equals(challenge.account().address())
                : parsed.address().equalsIgnoreCase(challenge.account().address());
        if (!addressMatches) {
            throw new VerificationException("address mismatch: expected '" + challenge.account().address()
                    + "', got '" + parsed.address() + "'");
        }

        String expectedChainId = challenge.chainId();
        String actualChainId = parsed.chainId();
        if (parsed.namespace() == Namespace.SOLANA) {
            try {
                SolanaCluster cluster = SolanaCluster.fromClusterName(parsed.chainId());
                actualChainId = cluster.genesisHash();
            } catch (IllegalArgumentException e) {
                throw new VerificationException("chainId mismatch (unsupported Solana cluster): " + parsed.chainId(), e);
            }
        }

        if (!actualChainId.equals(expectedChainId)) {
            throw new VerificationException(
                    "chainId mismatch: expected '" + expectedChainId + "', got '" + parsed.chainId() + "'");
        }
        // Consistency guard: nonce was the store key, so this mismatch indicates a store bug
        if (!parsed.nonce().equals(challenge.nonce())) {
            throw new VerificationException("nonce integrity error: store returned wrong challenge");
        }

        // Clock-skew tolerance check
        Instant now = clock.instant();
        java.time.Duration skew = policy.clockSkewTolerance();
        if (parsed.issuedAt().isAfter(now.plus(skew))) {
            throw new VerificationException("issuedAt is in the future");
        }
        if (!now.minus(skew).isBefore(parsed.expiresAt())) {
            throw new VerificationException("message expired per its own Expiration Time");
        }
    }
}
