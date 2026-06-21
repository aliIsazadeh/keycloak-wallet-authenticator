package com.w3auth.backend.infrastructure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "walletauth.refresh")
record RefreshProperties(Duration ttl) {}
