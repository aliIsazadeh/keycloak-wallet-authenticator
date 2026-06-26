package com.w3auth.backend.config;

import com.w3auth.backend.challenge.ChallengePolicy;
import com.w3auth.backend.challenge.ChallengeStore;
import com.w3auth.backend.identity.WalletIdentityStore;
import com.w3auth.backend.session.JwtService;
import com.w3auth.backend.session.RefreshTokenStore;
import com.w3auth.backend.usecase.Logout;
import com.w3auth.backend.usecase.RefreshSession;
import com.w3auth.backend.usecase.RequestChallenge;
import com.w3auth.backend.usecase.VerifyAndAuthenticate;
import com.w3auth.backend.verification.ChainClient;
import com.w3auth.backend.verification.ContractAwareSignatureVerifier;
import com.w3auth.backend.verification.EthereumSignatureVerifier;
import com.w3auth.backend.verification.SignatureVerifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

@Configuration
class UseCaseConfiguration {

    @Bean
    RequestChallenge requestChallenge(ChallengeStore store, ChallengePolicy policy, Clock clock) {
        return new RequestChallenge(store, policy, clock);
    }

    @Bean
    SignatureVerifier signatureVerifier(ChainClient chainClient) {
        return new ContractAwareSignatureVerifier(new EthereumSignatureVerifier(), chainClient);
    }

    @Bean
    VerifyAndAuthenticate verifyAndAuthenticate(
            ChallengeStore store, ChallengePolicy policy,
            SignatureVerifier signatureVerifier,
            WalletIdentityStore identityStore,
            RefreshTokenStore refreshTokenStore,
            JwtService jwtService, Clock clock) {
        return new VerifyAndAuthenticate(store, policy, signatureVerifier, identityStore, refreshTokenStore, jwtService, clock);
    }

    @Bean
    RefreshSession refreshSession(RefreshTokenStore refreshTokenStore,
                                  WalletIdentityStore walletIdentityStore,
                                  JwtService jwtService, Clock clock) {
        return new RefreshSession(refreshTokenStore, walletIdentityStore, jwtService, clock);
    }

    @Bean
    Logout logout(RefreshTokenStore refreshTokenStore) {
        return new Logout(refreshTokenStore);
    }
}
