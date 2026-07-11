package com.w3auth.backend.infrastructure;

import com.w3auth.backend.verification.ChainClient;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.http.HttpService;

@Configuration
@EnableConfigurationProperties(ChainProperties.class)
class ChainConfiguration {

    @Bean
    Web3j web3j(ChainProperties properties) {
        // Web3j.build is lazy: it creates an OkHttpClient and stores the URL; no network
        // connection is made at construction time. The bean is safe to create at boot
        // even if the RPC endpoint is unreachable.
        return Web3j.build(new HttpService(properties.rpcUrl()));
    }

    @Bean
    ChainClient chainClient(Web3j web3j) {
        return new Web3jChainClient(web3j);
    }
}
