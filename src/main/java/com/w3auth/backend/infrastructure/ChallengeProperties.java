package com.w3auth.backend.infrastructure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Binds {@code walletauth.challenge.*} to construct the {@link com.w3auth.backend.challenge.ChallengePolicy} bean.
 */
@ConfigurationProperties(prefix = "walletauth.challenge")
record ChallengeProperties(String domain, String uri, Duration nonceTtl) {
}
