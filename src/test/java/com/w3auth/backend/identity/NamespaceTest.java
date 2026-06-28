package com.w3auth.backend.identity;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NamespaceTest {

    @Test
    void parsesKnownNamespace() {
        assertThat(Namespace.fromString("eip155")).isEqualTo(Namespace.EIP155);
    }

    @Test
    void rejectsUnknownNamespace() {
        // "solana" is now a known namespace (M4); use a genuinely unknown one.
        assertThatThrownBy(() -> Namespace.fromString("cosmos"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void parsesKnownSolanaNamespace() {
        assertThat(Namespace.fromString("solana")).isEqualTo(Namespace.SOLANA);
    }

    @Test
    void solanaToStringReturnsCanonicalValue() {
        assertThat(Namespace.SOLANA).hasToString("solana");
    }

    @Test
    void isCaseSensitiveAndRejectsNonLowercaseVariants() {
        // CAIP-2 namespaces are lowercase ([-a-z0-9]{3,8}); "EIP155"/"Eip155"
        // are not normalized to "eip155", they are invalid.
        assertThatThrownBy(() -> Namespace.fromString("EIP155"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Namespace.fromString("Eip155"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void toStringReturnsCanonicalValue() {
        assertThat(Namespace.EIP155).hasToString("eip155");
    }
}
