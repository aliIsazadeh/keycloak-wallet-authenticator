package com.w3auth.backend.infrastructure;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for the startup guard in {@link JwtConfiguration#jwtPolicy}.
 * Lives in the same package so it can access the package-private class.
 */
class JwtConfigurationTest {

    private final JwtConfiguration config = new JwtConfiguration();

    @Test
    void jwtPolicy_validSecret_createsPolicy() {
        // 32-byte key base64-encoded (the local-dev default)
        String secret = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";
        JwtProperties properties = new JwtProperties(secret, Duration.ofMinutes(10), "wallet-auth");

        var policy = config.jwtPolicy(properties);

        assertThat(policy.signingKey()).isNotNull();
        assertThat(policy.ttl()).isEqualTo(Duration.ofMinutes(10));
        assertThat(policy.audience()).isEqualTo("wallet-auth");
    }

    @Test
    void jwtPolicy_secretTooShort_throwsIllegalStateException() {
        // 31 bytes — one below the 256-bit minimum. Encode as Base64 for the properties.
        String shortSecret = Base64.getEncoder().encodeToString(new byte[31]);
        JwtProperties properties = new JwtProperties(shortSecret, Duration.ofMinutes(10), "wallet-auth");

        assertThatThrownBy(() -> config.jwtPolicy(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("256 bits");
    }
}
