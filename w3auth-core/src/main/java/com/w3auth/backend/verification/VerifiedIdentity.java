package com.w3auth.backend.verification;

/**
 * The output of {@link SignatureVerifier#verify}: the address recovered from
 * the signature via ecrecover (or equivalent). The caller is responsible for
 * checking that this matches the address claimed in the SIWE message.
 */
public record VerifiedIdentity(String signerAddress) {

    public VerifiedIdentity {
        if (signerAddress == null || signerAddress.isBlank()) {
            throw new IllegalArgumentException("signerAddress must not be blank");
        }
    }
}
