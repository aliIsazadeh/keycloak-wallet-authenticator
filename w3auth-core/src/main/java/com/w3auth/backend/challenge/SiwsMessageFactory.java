package com.w3auth.backend.challenge;

import com.w3auth.backend.identity.Namespace;
import com.w3auth.backend.identity.SolanaCluster;

/**
 * Builds the canonical SIWS (Sign-In With Solana) message string for a
 * {@link Challenge}.
 *
 * <p>This is a pure formatter: it produces the exactly 10-line message to be
 * signed, but does not parse or verify a returned message (that is in
 * {@code verification}).
 *
 * <p><strong>Format:</strong> The payload format matches what
 * {@link com.w3auth.backend.verification.SiwsMessageParser} strictly expects:
 * a domain statement with the Solana suffix, exactly 2 blank lines, and the
 * standard 6 SIWS fields (URI, Version, Chain ID, Nonce, Issued At,
 * Expiration Time).
 */
public final class SiwsMessageFactory {

    private static final String VERSION = "1";

    private SiwsMessageFactory() {
    }

    /**
     * Builds the SIWS message to be signed for {@code challenge}.
     *
     * <p>Translates the CAIP-2 genesis hash stored in the challenge's
     * {@code chainId()} into the cluster string (e.g. "mainnet") required
     * by the SIWS message body.
     *
     * @throws IllegalArgumentException if the challenge namespace is not SOLANA,
     *         or if the chainId is not a known Solana genesis hash
     */
    public static String create(Challenge challenge) {
        if (challenge.account().namespace() != Namespace.SOLANA) {
            throw new IllegalArgumentException("SiwsMessageFactory requires a SOLANA challenge");
        }

        // The challenge stores the CAIP-2 genesis hash as the chainId.
        // SIWS messages require the cluster name (e.g. "mainnet").
        SolanaCluster cluster = SolanaCluster.fromGenesisHash(challenge.chainId());

        return challenge.domain() + " wants you to sign in with your Solana account:\n"
                + challenge.account().address() + "\n"
                + "\n"
                + "\n"
                + "URI: " + challenge.uri() + "\n"
                + "Version: " + VERSION + "\n"
                + "Chain ID: " + cluster.clusterName() + "\n"
                + "Nonce: " + challenge.nonce() + "\n"
                + "Issued At: " + challenge.issuedAt() + "\n"
                + "Expiration Time: " + challenge.expiresAt();
    }
}
