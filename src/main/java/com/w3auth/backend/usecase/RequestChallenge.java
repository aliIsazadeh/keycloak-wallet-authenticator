package com.w3auth.backend.usecase;

import com.w3auth.backend.challenge.Challenge;
import com.w3auth.backend.challenge.ChallengePolicy;
import com.w3auth.backend.challenge.ChallengeStore;
import com.w3auth.backend.challenge.Nonce;
import com.w3auth.backend.identity.CaipAccountId;

import java.time.Clock;
import java.time.Instant;

/**
 * Issues a challenge for a claimed wallet account: generates a nonce, builds
 * the {@link Challenge} with {@code issuedAt} from the injected {@link Clock}
 * and {@code expiresAt = issuedAt + policy.nonceTtl()}, stores it, and
 * returns it. The caller (the API layer) is responsible for converting the
 * returned {@code Challenge} to a SIWE message and a wire response.
 *
 * <p>This class is a plain Java object — no Spring annotations — so that
 * {@code usecase} stays framework-free and the ArchUnit guard can enforce it.
 * Wiring to Spring happens in {@code config.UseCaseConfiguration}.
 */
public class RequestChallenge {

    private final ChallengeStore store;
    private final ChallengePolicy policy;
    private final Clock clock;

    public RequestChallenge(ChallengeStore store, ChallengePolicy policy, Clock clock) {
        this.store = store;
        this.policy = policy;
        this.clock = clock;
    }

    /**
     * Issues and stores a challenge for {@code account}. The account is
     * accepted as-is — {@link CaipAccountId} enforces its own invariants at
     * construction, so structural invalidity cannot reach this method.
     */
    public Challenge execute(CaipAccountId account) {
        Instant issuedAt = clock.instant();
        String nonce = Nonce.generate();
        Challenge challenge = new Challenge(
                account, nonce, policy.domain(), policy.uri(),
                issuedAt, issuedAt.plus(policy.nonceTtl()));
        store.store(challenge);
        return challenge;
    }
}
