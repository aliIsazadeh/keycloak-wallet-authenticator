package com.w3auth.backend.usecase;

import com.w3auth.backend.challenge.Challenge;
import com.w3auth.backend.challenge.ChallengePolicy;
import com.w3auth.backend.challenge.ChallengeStore;
import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import com.w3auth.backend.verification.SignatureVerifier;
import com.w3auth.backend.verification.SiweMessage;
import com.w3auth.backend.verification.SiweMessageParser;
import com.w3auth.backend.verification.VerificationException;
import com.w3auth.backend.verification.VerificationRequest;
import com.w3auth.backend.verification.VerifiedIdentity;

import java.time.Clock;

/**
 * Orchestrates the full EIP-4361 verify flow: parse → consume nonce → validate
 * fields → verify signature → check signer → return authenticated account.
 *
 * <p>No Spring annotations — {@code usecase} is a core package. Wiring to
 * Spring happens in {@code config.UseCaseConfiguration}.
 */
public class VerifyAndAuthenticate {

    private final ChallengeStore challengeStore;
    private final ChallengePolicy policy;
    private final SignatureVerifier signatureVerifier;
    private final Clock clock;

    public VerifyAndAuthenticate(ChallengeStore challengeStore, ChallengePolicy policy,
                                 SignatureVerifier signatureVerifier, Clock clock) {
        this.challengeStore = challengeStore;
        this.policy = policy;
        this.signatureVerifier = signatureVerifier;
        this.clock = clock;
    }

    /**
     * Verifies a signed SIWE message and returns the authenticated wallet account.
     *
     * @param rawMessage the EIP-4361 plaintext exactly as presented for signing
     * @param signature  the hex-encoded signature from the wallet
     * @return the authenticated {@link CaipAccountId}
     * @throws VerificationException for any failure: malformed message, nonce
     *         missing/expired/reused, field mismatch, invalid signature, or
     *         signer-address mismatch
     */
    public CaipAccountId execute(String rawMessage, String signature) throws VerificationException {

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
        // Case-insensitive: ecrecover may return mixed-case; full canonicalization is in M1 step 3 (ecrecover)
        if (!verified.signerAddress().equalsIgnoreCase(parsed.address())) {
            throw new VerificationException(
                    "signer mismatch: recovered '" + verified.signerAddress()
                    + "' but message claims '" + parsed.address() + "'");
        }

        // Step 6: derive and return the authenticated account
        // CaipAccountId.of canonicalizes the address to lowercase
        return CaipAccountId.of(Namespace.EIP155, parsed.chainId(), parsed.address());
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
