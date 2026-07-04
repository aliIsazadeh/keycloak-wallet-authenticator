package com.w3auth.backend.config;

import com.w3auth.backend.challenge.ChallengePolicy;
import com.w3auth.backend.challenge.ChallengeStore;
import com.w3auth.backend.identity.WalletIdentityStore;
import com.w3auth.backend.session.JwtService;
import com.w3auth.backend.session.RefreshTokenStore;
import com.w3auth.backend.usecase.AuthEventStore;
import com.w3auth.backend.usecase.Logout;
import com.w3auth.backend.usecase.RefreshSession;
import com.w3auth.backend.usecase.RequestChallenge;
import com.w3auth.backend.usecase.VerifyAndAuthenticate;
import com.w3auth.backend.verification.ChainClient;
import com.w3auth.backend.verification.ContractAwareSignatureVerifier;
import com.w3auth.backend.verification.EthereumSignatureVerifier;
import com.w3auth.backend.verification.NamespaceRoutingSignatureVerifier;
import com.w3auth.backend.verification.SignatureVerifier;
import com.w3auth.backend.verification.SolanaSignatureVerifier;
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
        SignatureVerifier ethereum = new ContractAwareSignatureVerifier(new EthereumSignatureVerifier(), chainClient);
        SignatureVerifier solana = new SolanaSignatureVerifier();
        return new NamespaceRoutingSignatureVerifier(ethereum, solana);
    }

    @Bean
    VerifyAndAuthenticate verifyAndAuthenticate(
            ChallengeStore store, ChallengePolicy policy,
            SignatureVerifier signatureVerifier,
            WalletIdentityStore identityStore,
            RefreshTokenStore refreshTokenStore,
            JwtService jwtService, Clock clock,
            AuthEventStore authEventStore) {
        return new VerifyAndAuthenticate(store, policy, signatureVerifier, identityStore, refreshTokenStore, jwtService, clock, authEventStore);
    }

    @Bean
    RefreshSession refreshSession(RefreshTokenStore refreshTokenStore,
                                  WalletIdentityStore walletIdentityStore,
                                  JwtService jwtService, Clock clock,
                                  AuthEventStore authEventStore) {
        return new RefreshSession(refreshTokenStore, walletIdentityStore, jwtService, clock, authEventStore);
    }

    @Bean
    Logout logout(RefreshTokenStore refreshTokenStore, Clock clock, AuthEventStore authEventStore) {
        return new Logout(refreshTokenStore, clock, authEventStore);
    }
}
