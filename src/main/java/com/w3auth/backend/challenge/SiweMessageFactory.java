package com.w3auth.backend.challenge;

/**
 * Builds the canonical EIP-4361 (Sign-In with Ethereum) message string for a
 * {@link Challenge}.
 *
 * <p>This is a pure formatter: it produces the message to be signed, but does
 * not parse or verify a returned message (that is M1, in {@code verification}).
 *
 * <p><strong>Format:</strong> per the EIP-4361 ABNF, the optional
 * {@code [ statement LF ]} sits between two {@code LF}s following the address
 * line. With no statement, that collapses to two blank lines between the
 * address and {@code URI:} — confirmed against the reference implementation
 * (spruceid/siwe {@code toMessage()}), which produces the same. M0 omits the
 * statement block entirely; {@code ChallengePolicy} has no {@code statement}
 * field — one can be added if a real client needs it.
 *
 * <p><strong>Known M0 limitation:</strong> the {@code address} line uses
 * {@link com.w3auth.backend.identity.CaipAccountId}'s canonical lowercase
 * form, not the EIP-55 mixed-case checksum that wallets typically display.
 * Lowercase is cryptographically equivalent for signing/recovery, but may not
 * visually match the address as shown in the user's wallet. EIP-55 checksum
 * encoding requires Keccak-256 (distinct from JDK's SHA3-256) and is deferred
 * to M1, where address-comparison logic already needs to exist.
 */
public final class SiweMessageFactory {

    private static final String VERSION = "1";

    private SiweMessageFactory() {
    }

    /**
     * Builds the EIP-4361 message to be signed for {@code challenge}.
     */
    public static String create(Challenge challenge) {
        return challenge.domain() + " wants you to sign in with your Ethereum account:\n"
                + challenge.account().address() + "\n"
                + "\n"
                + "\n"
                + "URI: " + challenge.uri() + "\n"
                + "Version: " + VERSION + "\n"
                + "Chain ID: " + challenge.chainId() + "\n"
                + "Nonce: " + challenge.nonce() + "\n"
                + "Issued At: " + challenge.issuedAt() + "\n"
                + "Expiration Time: " + challenge.expiresAt();
    }
}
