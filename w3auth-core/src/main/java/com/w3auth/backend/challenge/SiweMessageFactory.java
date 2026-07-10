package com.w3auth.backend.challenge;

/**
 * Builds the canonical EIP-4361 (Sign-In with Ethereum) message string for a
 * {@link Challenge}.
 *
 * <p>This is a pure formatter: it produces the message to be signed, but does
 * not parse or verify a returned message (that is in {@code verification}).
 *
 * <p><strong>Format:</strong> per the EIP-4361 ABNF, the optional
 * {@code [ statement LF ]} sits between two {@code LF}s following the address
 * line. With no statement, that collapses to two blank lines between the
 * address and {@code URI:} — confirmed against the reference implementation
 * (spruceid/siwe {@code toMessage()}), which produces the same. This factory
 * omits the statement; {@code ChallengePolicy} has no {@code statement} field
 * and one can be added when a real client needs it. {@code SiweMessageParser}
 * accepts both forms (with and without statement).
 *
 * <p><strong>EIP-55 Checksum:</strong> the {@code address} line is formatted
 * using the EIP-55 checksum encoding (via web3j's {@code Keys.toChecksumAddress})
 * to match what wallets typically display and prevent wallet warnings.
 */
public final class SiweMessageFactory {

    private static final String VERSION = "1";

    private SiweMessageFactory() {
    }

    /**
     * Builds the EIP-4361 message to be signed for {@code challenge}.
     */
    public static String create(Challenge challenge) {
        String address = challenge.account().address();
        if (challenge.account().namespace() == com.w3auth.backend.identity.Namespace.EIP155) {
            address = org.web3j.crypto.Keys.toChecksumAddress(address);
        }
        return challenge.domain() + " wants you to sign in with your Ethereum account:\n"
                + address + "\n"
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
