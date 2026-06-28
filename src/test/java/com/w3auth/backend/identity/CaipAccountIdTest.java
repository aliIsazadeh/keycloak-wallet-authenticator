package com.w3auth.backend.identity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

// Solana address test vectors from the CAIP-10 Solana namespace profile
// (https://github.com/ChainAgnostic/CAIPs/blob/master/namespaces/solana/caip10.md):
//   7S3P4HxJpyyigGzodYwHtCxZyUQe9JiBMHyRWXArAaKv — example pubkey cited in the spec
//   11111111111111111111111111111111 — Solana System Program (all-zero 32-byte pubkey)

class CaipAccountIdTest {

    private static final String ADDRESS_LOWER = "0xabc1234567890abc1234567890abc12345678901";
    private static final String ADDRESS_UPPER = "0xABC1234567890ABC1234567890ABC12345678901";

    // Solana CAIP-2 chain references (first 32 chars of genesis hash in base58)
    private static final String SOLANA_REF_MAINNET = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
    private static final String SOLANA_REF_DEVNET  = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
    // Solana address test vectors (see file-level comment for sources)
    private static final String SOLANA_ADDR         = "7S3P4HxJpyyigGzodYwHtCxZyUQe9JiBMHyRWXArAaKv";
    private static final String SOLANA_SYSTEM_PROG  = "11111111111111111111111111111111";

    @Test
    void parsesValidCaip10String() {
        CaipAccountId account = CaipAccountId.parse("eip155:1:" + ADDRESS_LOWER);

        assertThat(account.namespace()).isEqualTo(Namespace.EIP155);
        assertThat(account.reference()).isEqualTo("1");
        assertThat(account.address()).isEqualTo(ADDRESS_LOWER);
        assertThat(account).hasToString("eip155:1:" + ADDRESS_LOWER);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",                                                                // empty string
            "eip155:1",                                                       // too few parts
            "eip155:1:0xabc1234567890abc1234567890abc12345678901:junk",       // too many parts (trailing junk)
            "solana:1:0xabc1234567890abc1234567890abc12345678901",            // solana: "1" is invalid reference (not 32-char base58); "0x..." is invalid address ('0' not in base58)
            "eip155:mainnet:0xabc1234567890abc1234567890abc12345678901",      // non-numeric reference
            "eip155:1:0xabc1234567890abc1234567890abc12345678",               // address too short
            "eip155:1:abc1234567890abc1234567890abc12345678901",              // missing 0x prefix
            "eip155:1:0xZZZ1234567890abc1234567890abc12345678901",            // invalid hex
            " eip155:1:0xabc1234567890abc1234567890abc12345678901",           // leading whitespace
            "eip155:1:0xabc1234567890abc1234567890abc12345678901 ",           // trailing whitespace
    })
    void rejectsInvalidFormat(String input) {
        assertThatThrownBy(() -> CaipAccountId.parse(input))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsNullInput() {
        assertThatThrownBy(() -> CaipAccountId.parse(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void twoCasesOfSameAddressProduceEqualObjects() {
        CaipAccountId lower = CaipAccountId.parse("eip155:1:" + ADDRESS_LOWER);
        CaipAccountId upper = CaipAccountId.parse("eip155:1:" + ADDRESS_UPPER);

        assertThat(lower).isEqualTo(upper);
        assertThat(lower).hasSameHashCodeAs(upper);
        assertThat(lower.address()).isEqualTo(ADDRESS_LOWER);
        assertThat(upper.address()).isEqualTo(ADDRESS_LOWER);
        assertThat(lower.identityKey()).isEqualTo(upper.identityKey());
    }

    @Test
    void ofFactoryValidatesAndCanonicalizes() {
        CaipAccountId account = CaipAccountId.of(Namespace.EIP155, "1", ADDRESS_UPPER);

        assertThat(account.address()).isEqualTo(ADDRESS_LOWER);
        assertThat(account.identityKey()).isEqualTo(new CaipAccountId.IdentityKey(Namespace.EIP155, ADDRESS_LOWER));
    }

    @Test
    void identityKeyExcludesChainReference() {
        CaipAccountId mainnet = CaipAccountId.of(Namespace.EIP155, "1", ADDRESS_LOWER);
        CaipAccountId polygon = CaipAccountId.of(Namespace.EIP155, "137", ADDRESS_LOWER);

        assertThat(mainnet).isNotEqualTo(polygon);
        assertThat(mainnet.identityKey()).isEqualTo(polygon.identityKey());
    }

    // -------------------------------------------------------------------------
    // Solana namespace tests
    // -------------------------------------------------------------------------

    @Test
    void parsesValidSolanaAccountId() {
        CaipAccountId account = CaipAccountId.parse(
                "solana:" + SOLANA_REF_MAINNET + ":" + SOLANA_ADDR);

        assertThat(account.namespace()).isEqualTo(Namespace.SOLANA);
        assertThat(account.reference()).isEqualTo(SOLANA_REF_MAINNET);
        assertThat(account.address()).isEqualTo(SOLANA_ADDR);
        assertThat(account).hasToString("solana:" + SOLANA_REF_MAINNET + ":" + SOLANA_ADDR);
    }

    @Test
    void solanaSystemProgramAddressIsAccepted() {
        // 32 '1' chars = 32 zero bytes; this is the real Solana System Program pubkey.
        CaipAccountId account = CaipAccountId.of(Namespace.SOLANA, SOLANA_REF_MAINNET, SOLANA_SYSTEM_PROG);
        assertThat(account.address()).isEqualTo(SOLANA_SYSTEM_PROG);
    }

    @Test
    void solanaAddressIsNotLowercased() {
        // Unlike EIP-155, base58 is case-sensitive; the address must be stored as-is.
        CaipAccountId account = CaipAccountId.of(Namespace.SOLANA, SOLANA_REF_MAINNET, SOLANA_ADDR);
        assertThat(account.address()).isEqualTo(SOLANA_ADDR);
    }

    @Test
    void solanaIdentityKeyExcludesChainReference() {
        CaipAccountId onMainnet = CaipAccountId.of(Namespace.SOLANA, SOLANA_REF_MAINNET, SOLANA_ADDR);
        CaipAccountId onDevnet  = CaipAccountId.of(Namespace.SOLANA, SOLANA_REF_DEVNET,  SOLANA_ADDR);

        assertThat(onMainnet).isNotEqualTo(onDevnet);
        assertThat(onMainnet.identityKey()).isEqualTo(onDevnet.identityKey());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "7S3P4H",                                           // valid base58 but decodes to ~4 bytes (< 32)
            "0xabc1234567890abc1234567890abc12345678901",       // EVM address — '0' and 'x' not in base58
            "OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO",                 // 'O' not in base58 alphabet
    })
    void rejectsInvalidSolanaAddress(String address) {
        assertThatThrownBy(() -> CaipAccountId.of(Namespace.SOLANA, SOLANA_REF_MAINNET, address))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "1",                                                // EVM-style decimal — wrong for Solana
            "mainnet",                                          // human name, only 7 chars
            "5eykt4UsFv8P8NJdTREpY1vzqKqZKvd",                // 31 chars (one short of 32)
            "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpa",              // 33 chars (one over 32)
    })
    void rejectsInvalidSolanaReference(String reference) {
        assertThatThrownBy(() -> CaipAccountId.of(Namespace.SOLANA, reference, SOLANA_ADDR))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void solanaAddressRejectedUnderEip155Namespace() {
        assertThatThrownBy(() -> CaipAccountId.of(Namespace.EIP155, "1", SOLANA_ADDR))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void evmAddressRejectedUnderSolanaNamespace() {
        assertThatThrownBy(() -> CaipAccountId.of(Namespace.SOLANA, SOLANA_REF_MAINNET, ADDRESS_LOWER))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
