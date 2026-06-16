package com.w3auth.backend.infrastructure;

import com.w3auth.backend.challenge.ChallengePolicy;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(ChallengeProperties.class)
class ChallengeConfiguration {

    @Bean
    ChallengePolicy challengePolicy(ChallengeProperties properties) {
        return new ChallengePolicy(properties.domain(), properties.uri(), properties.nonceTtl());
    }
}
