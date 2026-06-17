package com.w3auth.backend.challenge;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generates single-use challenge nonces.
 *
 * <p>Each nonce is 16 random bytes (128 bits) from a {@link SecureRandom}
 * CSPRNG, base64url-encoded without padding.
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
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
