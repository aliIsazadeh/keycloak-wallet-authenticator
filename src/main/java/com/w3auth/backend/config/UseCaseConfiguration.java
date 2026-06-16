package com.w3auth.backend.config;

import com.w3auth.backend.challenge.ChallengePolicy;
import com.w3auth.backend.challenge.ChallengeStore;
import com.w3auth.backend.usecase.RequestChallenge;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

@Configuration
class UseCaseConfiguration {

    // TODO(next): move Clock bean to its own config (it's an app primitive, not a use-case concern)
    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    RequestChallenge requestChallenge(ChallengeStore store, ChallengePolicy policy, Clock clock) {
        return new RequestChallenge(store, policy, clock);
    }
}
