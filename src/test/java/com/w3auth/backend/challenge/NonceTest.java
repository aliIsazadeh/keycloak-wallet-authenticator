package com.w3auth.backend.challenge;

import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class NonceTest {

    /**
     * Nonce.generate() encodes 16 raw bytes as base64url (no padding).
     * Decoding must yield >=16 bytes (128 bits) so that a predictable counter
     * or truncated CSPRNG output cannot satisfy this test.  128-bit entropy is
     * the minimum replay-attack defense: an attacker guessing nonces at
     * 1 billion/s would need ~10^19 years to find a collision.
     */
    @Test
    void generatesAtLeast128BitsOfEntropy() {
        String nonce = Nonce.generate();

        // base64url-decode to recover the raw bytes
        byte[] decoded = Base64.getUrlDecoder().decode(nonce);

        assertThat(decoded.length)
                .as("raw nonce bytes must be >= 16 (128 bits) to provide CSPRNG replay defense")
                .isGreaterThanOrEqualTo(16);
    }

    /** Uniqueness check: 1 000 nonces must all be distinct. */
    @Test
    void generatesUniqueValues() {
        Set<String> nonces = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            nonces.add(Nonce.generate());
        }

        assertThat(nonces).hasSize(1000);
    }
}
