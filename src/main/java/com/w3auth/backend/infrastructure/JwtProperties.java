package com.w3auth.backend.infrastructure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Binds {@code walletauth.jwt.*} to construct {@link com.w3auth.backend.session.JwtPolicy}.
 *
 * <p>{@code secret} must be a Base64-encoded value representing at least 32 bytes
 * (256 bits). Rejected at startup if too short.
 */
@ConfigurationProperties(prefix = "walletauth.jwt")
record JwtProperties(String secret, Duration ttl, String audience) {
}
