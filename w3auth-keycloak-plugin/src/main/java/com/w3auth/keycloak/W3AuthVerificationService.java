package com.w3auth.keycloak;

import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import com.w3auth.backend.identity.SolanaCluster;
import com.w3auth.backend.verification.*;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Shared SIWE/SIWS verification and user-provisioning logic used by both the browser
 * ({@link W3AuthAuthenticator}) and native direct-grant ({@link W3AuthDirectGrantAuthenticator})
 * flows.
 *
 * <p>Owns everything that is identical between the two flows: hex decode, namespace
 * detection + message parse, domain/uri/issuedAt/expiry validation, signature verification
 * (EOA/1271/6492 + Solana routing), signer-address matching, {@link CaipAccountId} derivation,
 * and user lookup/provisioning (including the pre-registration collision guard and the
 * v1.0.3 stock-realm profile-completion fix).
 *
 * <p>Deliberately does NOT touch either flow's nonce store and does NOT call
 * {@code context.success}/{@code challenge}/{@code failure} — those differ per flow (auth-session
 * note vs {@code SingleUseObjectProvider}; form re-challenge vs generic {@code invalid_grant}) and
 * are the caller's responsibility. Failures are signalled via typed exceptions the caller
 * translates into its own flow-appropriate response.
 */
final class W3AuthVerificationService {

    private W3AuthVerificationService() {
    }

    /**
     * Signals a pre-registration username collision: an existing user occupies the wallet's
     * identity-derived username but lacks (or mismatches) the wallet-binding attributes this
     * service writes at first provision. Distinguished from {@link VerificationException} so the
     * browser flow can keep its distinct "Authentication failed." message.
     */
    static final class BindingConflictException extends VerificationException {
        BindingConflictException(String message) {
            super(message);
        }
    }

    /** Result of a successful verify+provision: the parsed message, its derived account, and the user. */
    record VerifiedLogin(AuthMessage parsed, CaipAccountId account, UserModel user) {
    }

    /**
     * Decodes the hex-encoded SIWE/SIWS message back to its canonical UTF-8 bytes.
     * Accepts an optional {@code 0x} prefix. Fail-closed on any malformed input:
     * odd length, empty, or a non-hex character.
     */
    static String decodeHexMessage(String hex) {
        String clean = (hex.startsWith("0x") || hex.startsWith("0X")) ? hex.substring(2) : hex;
        if (clean.isEmpty() || clean.length() % 2 != 0) {
            throw new IllegalArgumentException("message hex must be non-empty with an even length");
        }
        byte[] bytes = new byte[clean.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int hi = Character.digit(clean.charAt(2 * i), 16);
            int lo = Character.digit(clean.charAt(2 * i + 1), 16);
            if (hi == -1 || lo == -1) {
                throw new IllegalArgumentException("message hex contains a non-hex character");
            }
            bytes[i] = (byte) ((hi << 4) | lo);
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static Namespace detectNamespace(String rawMessage) {
        if (rawMessage == null) {
            throw new IllegalArgumentException("message must not be null");
        }
        int firstNewLine = rawMessage.indexOf('\n');
        String firstLine = (firstNewLine == -1) ? rawMessage : rawMessage.substring(0, firstNewLine);
        if (firstLine.endsWith("\r")) {
            firstLine = firstLine.substring(0, firstLine.length() - 1);
        }
        if (firstLine.endsWith(" wants you to sign in with your Ethereum account:")) {
            return Namespace.EIP155;
        } else if (firstLine.endsWith(" wants you to sign in with your Solana account:")) {
            return Namespace.SOLANA;
        }
        throw new IllegalArgumentException("Unknown or unsupported authentication message format");
    }

    /** Namespace-detects and parses the decoded message bytes into a structured {@link AuthMessage}. */
    static AuthMessage parseMessage(String rawMessage) {
        Namespace namespace = detectNamespace(rawMessage);
        return switch (namespace) {
            case EIP155 -> SiweMessageParser.parse(rawMessage);
            case SOLANA -> SiwsMessageParser.parse(rawMessage);
        };
    }

    /**
     * Resolves the {@link CaipAccountId} a parsed message claims: the chain reference is the
     * message's chainId for EIP-155, or the CAIP-2 genesis hash for the named Solana cluster.
     * Exposed separately from {@link #verifyAndProvision} so callers can cross-check a claimed
     * account (e.g. against stored nonce notes) before signature verification runs.
     */
    static CaipAccountId deriveAccount(AuthMessage parsed) {
        String chainReference = parsed.chainId();
        if (parsed.namespace() == Namespace.SOLANA) {
            SolanaCluster cluster = SolanaCluster.fromClusterName(parsed.chainId());
            chainReference = cluster.genesisHash();
        }
        return CaipAccountId.of(parsed.namespace(), chainReference, parsed.address());
    }

    /**
     * Validates the parsed message's domain/uri/expiry, verifies the signature, matches the
     * signer to the message's claimed address, and looks up/provisions the corresponding
     * Keycloak user.
     *
     * @throws BindingConflictException if an existing user occupies the derived username without
     *         matching wallet-binding attributes (pre-registration collision)
     * @throws VerificationException for any other claim-validation failure (domain/uri/expiry
     *         mismatch, signature invalid, signer mismatch)
     */
    static VerifiedLogin verifyAndProvision(
            KeycloakSession session,
            RealmModel realm,
            AuthMessage parsed,
            String rawMessage,
            String signature,
            String expectedDomain,
            String expectedUri,
            String rpcUrl) throws VerificationException {

        Namespace namespace = parsed.namespace();

        if (!expectedDomain.equals(parsed.domain())) {
            throw new VerificationException("Domain mismatch: expected " + expectedDomain + " but got " + parsed.domain());
        }
        if (!expectedUri.equals(parsed.uri())) {
            throw new VerificationException("URI mismatch: expected " + expectedUri + " but got " + parsed.uri());
        }

        Instant now = Instant.now();
        Duration skew = Duration.ofMinutes(5);
        if (parsed.issuedAt().isAfter(now.plus(skew))) {
            throw new VerificationException("Message issuedAt is in the future.");
        }
        if (!now.minus(skew).isBefore(parsed.expiresAt())) {
            throw new VerificationException("Message has expired.");
        }

        SignatureVerifier solanaVerifier = new SolanaSignatureVerifier();
        SignatureVerifier ethereumVerifier;
        if (rpcUrl != null && !rpcUrl.isBlank()) {
            ChainClient chainClient = new HttpChainClient(rpcUrl);
            ethereumVerifier = new ContractAwareSignatureVerifier(new EthereumSignatureVerifier(), chainClient);
        } else {
            ethereumVerifier = new EthereumSignatureVerifier();
        }
        SignatureVerifier verifier = new NamespaceRoutingSignatureVerifier(ethereumVerifier, solanaVerifier);

        VerifiedIdentity verified = verifier.verify(new VerificationRequest(parsed, rawMessage, signature));

        boolean matches = (namespace == Namespace.SOLANA)
                ? verified.signerAddress().equals(parsed.address())
                : verified.signerAddress().equalsIgnoreCase(parsed.address());
        if (!matches) {
            throw new VerificationException("Recovered signer address " + verified.signerAddress()
                    + " does not match message address " + parsed.address());
        }

        CaipAccountId account = deriveAccount(parsed);

        // Map username to identityKey to maintain address-based identity (casing normalized by CaipAccountId)
        String username = account.identityKey().toJwtSubject();

        UserModel user = session.users().getUserByUsername(realm, username);

        if (user == null) {
            user = session.users().addUser(realm, username);
            user.setEnabled(true);
            user.setAttribute("w3auth_address", List.of(parsed.address()));
            user.setAttribute("w3auth_namespace", List.of(namespace.name()));
            user.setAttribute("w3auth_chainId", List.of(parsed.chainId()));

            // Keycloak 25's default declarative user profile requires firstName /
            // lastName / email for the "user" role. A bare wallet-provisioned user has
            // none of those, which trips the dynamic VERIFY_PROFILE required action and
            // diverts a successful wallet login to an "Update Account Information" form
            // on any realm an operator hasn't customized — see
            // docs/investigation-stock-realm-required-actions.md. Removing pending
            // required actions on the user does not help: VERIFY_PROFILE is evaluated
            // from profile completeness at login time, not read off a static per-user
            // flag (confirmed empirically — see this fix's commit message). Completing
            // the profile is what actually satisfies the check. These values are
            // deliberately address-derived placeholders, not fabricated human data, so
            // an operator looking at the admin console can tell at a glance they're
            // synthetic. emailVerified=true is set defensively in case an operator has
            // also turned on the realm's separate verifyEmail setting.
            user.setFirstName("Wallet");
            user.setLastName(account.address());
            user.setEmail(account.address() + "@wallet.invalid");
            user.setEmailVerified(true);
        } else {
            // Guard against username pre-registration: a realm with self-registration
            // enabled lets an attacker create "eip155:0x<victim>" via the normal form
            // before the victim ever wallet-logs-in. Without this check a valid SIWE
            // from the victim silently binds to the attacker's account. Require the
            // wallet-binding attributes that this service writes at first-provision.
            //
            // Explicit account linking (form-registered account -> wallet) is out of
            // scope for V1. Do not add auto-claim logic here.
            String storedNamespace = user.getFirstAttribute("w3auth_namespace");
            String storedAddress = user.getFirstAttribute("w3auth_address");
            boolean namespaceOk = namespace.name().equals(storedNamespace);
            // EVM addresses are case-insensitive (EIP-55 checksum casing varies across
            // wallets); Solana Base58 addresses are case-sensitive.
            boolean addressOk = (namespace == Namespace.SOLANA)
                    ? parsed.address().equals(storedAddress)
                    : parsed.address().equalsIgnoreCase(storedAddress);
            if (!namespaceOk || !addressOk) {
                // Generic message: do not tell the client why the binding check failed
                // (would reveal whether a pre-registered username collision exists).
                throw new BindingConflictException("wallet-binding mismatch for username " + username);
            }
        }

        return new VerifiedLogin(parsed, account, user);
    }
}
