package com.w3auth.backend.identity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CaipAccountIdTest {

    private static final String ADDRESS_LOWER = "0xabc1234567890abc1234567890abc12345678901";
    private static final String ADDRESS_UPPER = "0xABC1234567890ABC1234567890ABC12345678901";

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
            "solana:1:0xabc1234567890abc1234567890abc12345678901",            // unsupported namespace
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
}
