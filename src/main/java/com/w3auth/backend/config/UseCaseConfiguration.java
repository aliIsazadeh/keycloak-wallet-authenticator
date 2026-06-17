package com.w3auth.backend.config;

import com.w3auth.backend.challenge.ChallengePolicy;
import com.w3auth.backend.challenge.ChallengeStore;
import com.w3auth.backend.usecase.RequestChallenge;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

@Configuration
class UseCaseConfiguration {

    @Bean
    RequestChallenge requestChallenge(ChallengeStore store, ChallengePolicy policy, Clock clock) {
        return new RequestChallenge(store, policy, clock);
    }
}
