package com.w3auth.backend.verification;

import com.w3auth.backend.identity.SolanaPublicKey;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

/**
 * Ed25519 signature verifier for Solana wallet authentication.
 *
 * <p><b>Ed25519 is verify-against-key, not recover-then-compare.</b> Unlike
 * {@link EthereumSignatureVerifier}, which uses ecrecover to derive a signer
 * address and hands it back for the caller to compare, Ed25519 takes the public
 * key as an input and returns a boolean. There is no address to recover; a false
 * result means the signature does not match the key and is thrown as a
 * {@link VerificationException} rather than returned as a different identity.
 * Returning a {@link VerifiedIdentity} on false would be a silent auth bypass.
 *
 * <p><b>Standalone in M4 piece 3.</b> This class does not implement
 * {@link SignatureVerifier} and does not touch {@link VerificationRequest}.
 * Seam wiring (interface generalization, namespace router, request shape) is
 * deferred to piece 4, where both concrete verifiers and the API layer exist
 * to constrain the design.
 *
 * <p>The caller is responsible for comparing {@link VerifiedIdentity#signerAddress()}
 * against the address claimed in the auth message — the same separation of concerns
 * that applies to the EVM verifier.
 */
public final class SolanaSignatureVerifier {

    /**
     * Verifies an Ed25519 {@code signature} over {@code message} against the
     * Ed25519 public key encoded in {@code base58Address}.
     *
     * @param message       the raw bytes that were signed
     * @param signature     the 64-byte Ed25519 signature
     * @param base58Address the Solana wallet address (base58-encoded 32-byte Ed25519 public key)
     * @return a {@link VerifiedIdentity} whose {@code signerAddress} is {@code base58Address}
     *         — the caller must compare this against the address in the auth message
     * @throws VerificationException if the address is malformed, the signature has wrong
     *         length, or the signature does not verify (thrown, not returned — see class doc)
     */
    public VerifiedIdentity verify(byte[] message, byte[] signature, String base58Address)
            throws VerificationException {

        // Step 1: decode and validate the address to 32 raw public-key bytes.
        byte[] publicKeyBytes;
        try {
            publicKeyBytes = SolanaPublicKey.decode(base58Address);
        } catch (IllegalArgumentException e) {
            throw new VerificationException(
                    "invalid Solana address '" + base58Address + "': " + e.getMessage(), e);
        }

        // Step 2: structural checks on message and signature before touching Ed25519.
        if (message == null) {
            throw new VerificationException("message must not be null");
        }
        if (signature == null || signature.length != 64) {
            int got = (signature == null) ? 0 : signature.length;
            throw new VerificationException("signature must be 64 bytes, got " + got);
        }

        // Step 3: low-level Ed25519 verification on raw bytes via BouncyCastle.
        // Ed25519.verify returns false for a well-formed but non-matching signature;
        // it does not throw. A false result is thrown (not returned) — see class doc.
        boolean valid = Ed25519.verify(signature, 0, publicKeyBytes, 0, message, 0, message.length);

        if (!valid) {
            throw new VerificationException("signature does not verify against public key");
        }

        return new VerifiedIdentity(base58Address);
    }
}
