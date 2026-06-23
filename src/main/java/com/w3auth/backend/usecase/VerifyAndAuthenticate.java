package com.w3auth.backend.usecase;

import com.w3auth.backend.challenge.Challenge;
import com.w3auth.backend.challenge.ChallengePolicy;
import com.w3auth.backend.challenge.ChallengeStore;
import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import com.w3auth.backend.identity.WalletIdentity;
import com.w3auth.backend.identity.WalletIdentityStore;
import com.w3auth.backend.session.JwtService;
import com.w3auth.backend.session.RefreshTokenStore;
import com.w3auth.backend.session.TokenGrant;
import com.w3auth.backend.verification.SignatureVerifier;
import com.w3auth.backend.verification.SiweMessage;
import com.w3auth.backend.verification.SiweMessageParser;
import com.w3auth.backend.verification.VerificationException;
import com.w3auth.backend.verification.VerificationRequest;
import com.w3auth.backend.verification.VerifiedIdentity;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * Orchestrates the full EIP-4361 verify flow: parse → consume nonce → validate
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

    public VerifyAndAuthenticate(ChallengeStore challengeStore, ChallengePolicy policy,
                                 SignatureVerifier signatureVerifier,
                                 WalletIdentityStore identityStore,
                                 RefreshTokenStore refreshTokenStore,
                                 JwtService jwtService, Clock clock) {
        this.challengeStore = challengeStore;
        this.policy = policy;
        this.signatureVerifier = signatureVerifier;
        this.identityStore = identityStore;
        this.refreshTokenStore = refreshTokenStore;
        this.jwtService = jwtService;
        this.clock = clock;
    }

    /**
     * Verifies a signed SIWE message and returns an access JWT for the authenticated wallet.
     *
     * @param rawMessage the EIP-4361 plaintext exactly as presented for signing
     * @param signature  the hex-encoded signature from the wallet
     * @return an {@link AuthResult} containing the access token and its expiry
     * @throws VerificationException for any failure: malformed message, nonce
     *         missing/expired/reused, field mismatch, invalid signature, or
     *         signer-address mismatch
     */
    public AuthResult execute(String rawMessage, String signature) throws VerificationException {

        // Step 1: parse the message — fail fast before touching the nonce store
        SiweMessage parsed;
        try {
            parsed = SiweMessageParser.parse(rawMessage);
        } catch (IllegalArgumentException e) {
            throw new VerificationException("malformed SIWE message: " + e.getMessage(), e);
        }

        // Step 2: atomically consume the nonce — replay gate, must precede all sig work.
        // If two concurrent requests arrive with the same nonce, exactly one GETDEL wins;
        // the other sees empty here and fails. There is no race between this and step 4.
        Challenge challenge = challengeStore.consume(parsed.nonce())
                .orElseThrow(() -> new VerificationException(
                        "nonce missing, expired, or already used"));

        // Step 3: field validation — message must match what the server issued
        validateFields(parsed, challenge);

        // Step 4: signature verification (ecrecover in production; injected for tests)
        VerifiedIdentity verified = signatureVerifier.verify(new VerificationRequest(parsed, rawMessage, signature));

        // Step 5: signer must equal the address the message claims
        if (!verified.signerAddress().equalsIgnoreCase(parsed.address())) {
            throw new VerificationException(
                    "signer mismatch: recovered '" + verified.signerAddress()
                    + "' but message claims '" + parsed.address() + "'");
        }

        // Step 6: upsert wallet identity (first durable write)
        CaipAccountId account = CaipAccountId.of(Namespace.EIP155, parsed.chainId(), parsed.address());
        WalletIdentity identity = identityStore.upsertOnLogin(account);

        // Step 7: issue access JWT and first refresh token of a new family. Capture issuedAt
        // once so the embedded iat and the returned expiresAt are derived from the same
        // instant — no clock-tick drift. refresh issue() comes after upsert so a row is only
        // written for a fully-successful login.
        Instant issuedAt = clock.instant();
        String token = jwtService.issue(account.identityKey(), issuedAt);
        TokenGrant grant = refreshTokenStore.issue(identity.id(), UUID.randomUUID());
        return new AuthResult(token, grant.rawToken(), issuedAt.plus(jwtService.ttl()));
    }

    private void validateFields(SiweMessage parsed, Challenge challenge) throws VerificationException {
        if (!parsed.domain().equals(policy.domain())) {
            throw new VerificationException(
                    "domain mismatch: expected '" + policy.domain() + "', got '" + parsed.domain() + "'");
        }
        if (!parsed.uri().equals(policy.uri())) {
            throw new VerificationException(
                    "uri mismatch: expected '" + policy.uri() + "', got '" + parsed.uri() + "'");
        }
        if (!"1".equals(parsed.version())) {
            throw new VerificationException("unsupported SIWE version: '" + parsed.version() + "'");
        }
        if (!parsed.chainId().equals(challenge.chainId())) {
            throw new VerificationException(
                    "chainId mismatch: expected '" + challenge.chainId() + "', got '" + parsed.chainId() + "'");
        }
        // Consistency guard: nonce was the store key, so this mismatch indicates a store bug
        if (!parsed.nonce().equals(challenge.nonce())) {
            throw new VerificationException("nonce integrity error: store returned wrong challenge");
        }
        if (parsed.issuedAt().isAfter(clock.instant())) {
            throw new VerificationException("issuedAt is in the future");
        }
        if (!clock.instant().isBefore(parsed.expiresAt())) {
            throw new VerificationException("message expired per its own Expiration Time");
        }
    }
}
