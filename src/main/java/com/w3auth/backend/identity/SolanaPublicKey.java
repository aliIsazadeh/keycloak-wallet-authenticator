package com.w3auth.backend.identity;

/**
 * Decodes a Solana base58 address to its 32 raw Ed25519 public-key bytes.
 *
 * <p>Single authoritative source for the "base58 → 32 bytes + length check"
 * logic. {@link Namespace#SOLANA}'s {@code validateAddress} delegates to this
 * class so the decode and length check never happen in two places.
 *
 * <p>{@link Base58} stays package-private; this class is the narrow public
 * seam that exposes only what the verification layer needs.
 */
public final class SolanaPublicKey {

    private SolanaPublicKey() {}

    /**
     * Decodes {@code base58Address} to its 32 raw Ed25519 public-key bytes.
     *
     * <p>Error messages are identical to those previously thrown inline by
     * {@code Namespace.SOLANA.validateAddress} — this is a behavior-preserving
     * extraction, not a rewording.
     *
     * @throws IllegalArgumentException if {@code base58Address} is null,
     *         contains characters outside the base58 alphabet, or does not
     *         decode to exactly 32 bytes
     */
    public static byte[] decode(String base58Address) {
        if (base58Address == null) {
            throw new IllegalArgumentException("Invalid solana address: null");
        }
        byte[] decoded;
        try {
            decoded = Base58.decode(base58Address);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Invalid solana address (not valid base58): " + base58Address, e);
        }
        if (decoded.length != 32) {
            throw new IllegalArgumentException(
                    "Invalid solana address (decoded to "
                    + decoded.length + " bytes, expected 32): " + base58Address);
        }
        return decoded;
    }
}
