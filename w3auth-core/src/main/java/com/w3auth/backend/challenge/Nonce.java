package com.w3auth.backend.challenge;

import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * Generates single-use challenge nonces.
 *
 * <p>Each nonce is 16 random bytes (128 bits) from a {@link SecureRandom}
 * CSPRNG, hex-encoded to 32 lowercase characters. EIP-4361 defines the SIWE
 * nonce grammar as {@code nonce = 8*( ALPHA / DIGIT )} — ASCII alphanumeric
 * only. Base64url output can contain {@code -} and {@code _}, which strict
 * wallets (confirmed: MetaMask) reject as invalid message formatting. Hex
 * keeps the same 128 bits of entropy while staying alphanumeric.
 */
public final class Nonce {

    private static final int NONCE_BYTES = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Nonce() {
    }

    /**
     * Generates a new random nonce.
     */
    public static String generate() {
        byte[] bytes = new byte[NONCE_BYTES];
        RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }
}
