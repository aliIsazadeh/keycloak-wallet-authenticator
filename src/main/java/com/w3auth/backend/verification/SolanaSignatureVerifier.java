package com.w3auth.backend.verification;

import com.w3auth.backend.identity.Base58;
import com.w3auth.backend.identity.SolanaPublicKey;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

import java.nio.charset.StandardCharsets;

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
 * <p>The caller is responsible for comparing {@link VerifiedIdentity#signerAddress()}
 * against the address claimed in the auth message — the same separation of concerns
 * that applies to the EVM verifier.
 */
public final class SolanaSignatureVerifier implements SignatureVerifier {

    @Override
    public VerifiedIdentity verify(VerificationRequest request) throws VerificationException {
        if (!(request.message() instanceof SiwsMessage)) {
            throw new IllegalArgumentException("SolanaSignatureVerifier only supports SiwsMessage");
        }

        byte[] messageBytes = request.rawMessage().getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = decodeSignature(request.signature());

        return verify(messageBytes, signatureBytes, request.message().address());
    }

    private static byte[] decodeSignature(String sigStr) throws VerificationException {
        if (sigStr == null || sigStr.isBlank()) {
            throw new VerificationException("signature must not be blank");
        }

        // Try hex decoding first if it matches hex format.
        // A 64-byte signature is 128 hex characters.
        String clean = (sigStr.startsWith("0x") || sigStr.startsWith("0X")) ? sigStr.substring(2) : sigStr;
        if (clean.length() == 128 && isHexString(clean)) {
            return hexToBytes(clean);
        }

        // Otherwise assume base58
        try {
            return Base58.decode(sigStr);
        } catch (IllegalArgumentException e) {
            throw new VerificationException("signature is neither valid hex nor valid base58", e);
        }
    }

    private static boolean isHexString(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.digit(s.charAt(i), 16) == -1) {
                return false;
            }
        }
        return true;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

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
