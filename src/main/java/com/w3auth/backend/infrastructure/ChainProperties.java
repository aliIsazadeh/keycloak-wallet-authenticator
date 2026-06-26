package com.w3auth.backend.infrastructure;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Binds {@code walletauth.chain.*} to configure the EVM JSON-RPC endpoint.
 */
@ConfigurationProperties(prefix = "walletauth.chain")
record ChainProperties(String rpcUrl) {
}
