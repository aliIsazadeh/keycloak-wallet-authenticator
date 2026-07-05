package com.w3auth.backend.challenge;

import java.util.Optional;

/**
 * Port for the ephemeral challenge store. Challenges are never written to
 * Postgres — the only implementation (M0) is Redis-backed, keyed by nonce,
 * with the TTL from {@link ChallengePolicy#nonceTtl()}.
 */
public interface ChallengeStore {

    /**
     * Stores a challenge, keyed by its nonce, with the policy's nonce TTL.
     */
    void store(Challenge challenge);

    /**
     * Atomically retrieves and deletes the challenge for {@code nonce}, so
     * that two concurrent calls cannot both succeed. Returns empty if the
     * nonce is missing, expired, or already consumed.
     */
    Optional<Challenge> consume(String nonce);
}
