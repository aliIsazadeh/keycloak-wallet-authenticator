package com.w3auth.backend.challenge;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class NonceTest {

    /**
     * Nonce.generate() hex-encodes 16 raw bytes (128 bits). The nonce must
     * match the hex charset and must decode back to exactly 16 bytes, so that
     * a predictable counter or truncated CSPRNG output cannot satisfy this
     * test. 128-bit entropy is the minimum replay-attack defense: an attacker
     * guessing nonces at 1 billion/s would need ~10^19 years to find a
     * collision.
     */
    @Test
    void generatesAtLeast128BitsOfEntropy() {
        String nonce = Nonce.generate();

        assertThat(nonce).matches("^[0-9a-f]{32}$");
        assertThat(HexFormat.of().parseHex(nonce).length)
                .as("raw nonce bytes must be 16 (128 bits) to provide CSPRNG replay defense")
                .isEqualTo(16);
    }

    /**
     * Regression guard for the EIP-4361 nonce grammar bug: SIWE requires
     * {@code nonce = 8*( ALPHA / DIGIT )}, i.e. plain alphanumeric. A prior
     * base64url encoding could emit '-' or '_', which strict wallets
     * (confirmed: MetaMask) reject as invalid message formatting.
     */
    @Test
    void matchesEip4361AlphanumericNonceGrammar() {
        String nonce = Nonce.generate();

        assertThat(nonce).matches("^[A-Za-z0-9]{8,}$");
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
