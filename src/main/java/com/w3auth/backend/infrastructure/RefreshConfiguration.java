package com.w3auth.backend.infrastructure;

import com.w3auth.backend.session.RefreshTokenPolicy;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(RefreshProperties.class)
class RefreshConfiguration {

    @Bean
    RefreshTokenPolicy refreshTokenPolicy(RefreshProperties properties) {
        return new RefreshTokenPolicy(properties.ttl());
    }
}
