package com.w3auth.backend.verification;

import com.w3auth.backend.identity.Namespace;

import java.util.Objects;

/**
 * Routes signature verification to the appropriate verifier based on the
 * message's namespace.
 *
 * <p>V1 supports EIP155 (Ethereum EVM) and SOLANA (Solana).
 */
public final class NamespaceRoutingSignatureVerifier implements SignatureVerifier {

    private final SignatureVerifier ethereumVerifier;
    private final SignatureVerifier solanaVerifier;

    public NamespaceRoutingSignatureVerifier(SignatureVerifier ethereumVerifier, SignatureVerifier solanaVerifier) {
        this.ethereumVerifier = Objects.requireNonNull(ethereumVerifier, "ethereumVerifier must not be null");
        this.solanaVerifier = Objects.requireNonNull(solanaVerifier, "solanaVerifier must not be null");
    }

    @Override
    public VerifiedIdentity verify(VerificationRequest request) throws VerificationException {
        Namespace namespace = request.message().namespace();
        return switch (namespace) {
            case EIP155 -> ethereumVerifier.verify(request);
            case SOLANA -> solanaVerifier.verify(request);
        };
    }
}
