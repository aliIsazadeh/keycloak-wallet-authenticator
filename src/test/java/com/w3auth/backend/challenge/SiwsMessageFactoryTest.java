package com.w3auth.backend.challenge;

import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SiwsMessageFactoryTest {

    private static final String DOMAIN = "example.com";
    private static final String URI = "https://example.com/login";
    private static final String ADDRESS = "586Z7H2vpX9qNhN2T4e9Utugie3ogjbxzGaMtM3E6HR5";
    private static final String MAINNET_GENESIS = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
    private static final String NONCE = "1234567890abcdef";
    private static final Instant ISSUED_AT = Instant.parse("2024-01-01T12:00:00Z");
    private static final Instant EXPIRES_AT = Instant.parse("2024-01-01T12:05:00Z");

    @Test
    void create_formatsCorrectSiwsMessage() {
        CaipAccountId account = CaipAccountId.of(Namespace.SOLANA, MAINNET_GENESIS, ADDRESS);
        Challenge challenge = new Challenge(account, NONCE, DOMAIN, URI, ISSUED_AT, EXPIRES_AT);

        String message = SiwsMessageFactory.create(challenge);

        String expected = "example.com wants you to sign in with your Solana account:\n"
                + "586Z7H2vpX9qNhN2T4e9Utugie3ogjbxzGaMtM3E6HR5\n"
                + "\n"
                + "\n"
                + "URI: https://example.com/login\n"
                + "Version: 1\n"
                + "Chain ID: mainnet\n"
                + "Nonce: 1234567890abcdef\n"
                + "Issued At: 2024-01-01T12:00:00Z\n"
                + "Expiration Time: 2024-01-01T12:05:00Z";

        assertThat(message).isEqualTo(expected);
    }

    @Test
    void create_throwsIfNamespaceNotSolana() {
        CaipAccountId evmAccount = CaipAccountId.of(Namespace.EIP155, "1", "0x0000000000000000000000000000000000000000");
        Challenge challenge = new Challenge(evmAccount, NONCE, DOMAIN, URI, ISSUED_AT, EXPIRES_AT);

        assertThatThrownBy(() -> SiwsMessageFactory.create(challenge))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("SiwsMessageFactory requires a SOLANA challenge");
    }

    @Test
    void create_throwsIfClusterUnknown() {
        // A valid 32 character base58 string but not one of the 3 known genesis hashes
        String unknownGenesis = "11111111111111111111111111111111";
        CaipAccountId account = CaipAccountId.of(Namespace.SOLANA, unknownGenesis, ADDRESS);
        Challenge challenge = new Challenge(account, NONCE, DOMAIN, URI, ISSUED_AT, EXPIRES_AT);

        assertThatThrownBy(() -> SiwsMessageFactory.create(challenge))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported Solana genesis hash");
    }
}
