package com.w3auth.backend.infrastructure;

import com.w3auth.backend.challenge.Challenge;
import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;

import java.time.Instant;

/**
 * Flat JSON shape for a {@link Challenge}, stored as the value at
 * {@code challenge:{nonce}}. Keeps Jackson annotations and JSON concerns out
 * of the core {@code challenge}/{@code identity} packages.
 */
record RedisChallengeRecord(
        String namespace,
        String reference,
        String address,
        String nonce,
        String domain,
        String uri,
        Instant issuedAt,
        Instant expiresAt) {

    static RedisChallengeRecord from(Challenge challenge) {
        CaipAccountId account = challenge.account();
        return new RedisChallengeRecord(
                account.namespace().value(),
                account.reference(),
                account.address(),
                challenge.nonce(),
                challenge.domain(),
                challenge.uri(),
                challenge.issuedAt(),
                challenge.expiresAt());
    }

    Challenge toChallenge() {
        CaipAccountId account = CaipAccountId.of(Namespace.fromString(namespace), reference, address);
        return new Challenge(account, nonce, domain, uri, issuedAt, expiresAt);
    }
}
