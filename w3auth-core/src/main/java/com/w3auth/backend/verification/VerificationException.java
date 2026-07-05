package com.w3auth.backend.verification;

/**
 * Thrown by {@link SignatureVerifier} and {@code VerifyAndAuthenticate} when
 * a verify request cannot be authenticated. All failure paths — nonce missing,
 * field mismatch, signature invalid, signer mismatch — use this exception so
 * the caller has a single checked type to handle and cannot accidentally let
 * a verification failure propagate as an unchecked exception.
 */
public class VerificationException extends Exception {

    public VerificationException(String message) {
        super(message);
    }

    public VerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
