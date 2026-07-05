package com.w3auth.backend.verification;

/**
 * Port for EIP-4361 signature verification. V1 has exactly one implementation:
 * {@code EthereumSignatureVerifier} (EOA ecrecover). The interface exists as a
 * test seam so {@code VerifyAndAuthenticate} can be exercised without crypto,
 * not as a future-protocol abstraction (rule of three).
 */
public interface SignatureVerifier {

    /**
     * Recovers the signer address from the signature in {@code request}.
     *
     * @throws VerificationException if the signature is structurally invalid
     *         or the recovery fails
     */
    VerifiedIdentity verify(VerificationRequest request) throws VerificationException;
}
