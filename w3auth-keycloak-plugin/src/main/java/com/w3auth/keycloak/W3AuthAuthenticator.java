package com.w3auth.keycloak;

import com.w3auth.backend.challenge.Nonce;
import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import com.w3auth.backend.identity.SolanaCluster;
import com.w3auth.backend.verification.*;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Custom Keycloak Authenticator that validates Web3 signatures (SIWE/SIWS)
 * and provisions or logs in a corresponding Keycloak user.
 */
public class W3AuthAuthenticator implements Authenticator {

    private static final String NONCE_NOTE = "w3auth-nonce";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.challenge(buildLoginForm(context, null));
    }

    private Response buildLoginForm(AuthenticationFlowContext context, String error) {
        String nonce = Nonce.generate();
        context.getAuthenticationSession().setAuthNote(NONCE_NOTE, nonce);

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        Map<String, String> configMap = config != null ? config.getConfig() : Map.of();
        String expectedDomain = getConfigValue(configMap, "expected-domain", "localhost");
        String expectedUri = getConfigValue(configMap, "expected-uri", "http://localhost:8080");

        LoginFormsProvider form = context.form()
                .setAttribute("nonce", nonce)
                .setAttribute("expectedDomain", expectedDomain)
                .setAttribute("expectedUri", expectedUri);

        if (error != null) {
            form = form.setError(error);
        }

        return form.createForm("w3auth-login.ftl");
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String accountIdStr = formData.getFirst("accountId");
        String messageHex = formData.getFirst("messageHex");
        String signature = formData.getFirst("signature");

        if (accountIdStr == null || messageHex == null || signature == null ||
                accountIdStr.isBlank() || messageHex.isBlank() || signature.isBlank()) {
            context.challenge(buildLoginForm(context, "Missing wallet login credentials"));
            return;
        }

        // Byte-exact transport: the client submits the message as hex of the exact bytes the
        // wallet signed, never as plaintext. An HTML form's application/x-www-form-urlencoded
        // serializer normalizes "\n" -> "\r\n", which corrupts the signed bytes and breaks
        // EIP-191 recovery (the signer recovers over different bytes than the wallet signed).
        // Hex-decoding here reconstructs the canonical bytes; those same bytes feed both SIWE
        // parsing and the verifier's EIP-191 hash, so signed-bytes == verified-bytes.
        String rawMessage;
        try {
            rawMessage = decodeHexMessage(messageHex);
        } catch (IllegalArgumentException e) {
            context.challenge(buildLoginForm(context, "Malformed wallet login message encoding"));
            return;
        }

        String storedNonce = context.getAuthenticationSession().getAuthNote(NONCE_NOTE);
        if (storedNonce == null) {
            context.challenge(buildLoginForm(context, "Login session expired. Please reload."));
            return;
        }

        try {
            Namespace namespace = detectNamespace(rawMessage);
            AuthMessage parsed = switch (namespace) {
                case EIP155 -> SiweMessageParser.parse(rawMessage);
                case SOLANA -> SiwsMessageParser.parse(rawMessage);
            };

            if (!storedNonce.equals(parsed.nonce())) {
                throw new VerificationException("Nonce mismatch. Potential replay attack.");
            }

            AuthenticatorConfigModel config = context.getAuthenticatorConfig();
            Map<String, String> configMap = config != null ? config.getConfig() : Map.of();
            String expectedDomain = getConfigValue(configMap, "expected-domain", "localhost");
            String expectedUri = getConfigValue(configMap, "expected-uri", "http://localhost:8080");
            String rpcUrl = getConfigValue(configMap, "ethereum-rpc-url", null);

            if (!expectedDomain.equals(parsed.domain())) {
                throw new VerificationException("Domain mismatch: expected " + expectedDomain + " but got " + parsed.domain());
            }
            if (!expectedUri.equals(parsed.uri())) {
                throw new VerificationException("URI mismatch: expected " + expectedUri + " but got " + parsed.uri());
            }

            Instant now = Instant.now();
            java.time.Duration skew = java.time.Duration.ofMinutes(5);
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

            String chainReference = parsed.chainId();
            if (namespace == Namespace.SOLANA) {
                SolanaCluster cluster = SolanaCluster.fromClusterName(parsed.chainId());
                chainReference = cluster.genesisHash();
            }
            CaipAccountId account = CaipAccountId.of(namespace, chainReference, parsed.address());
            
            // Map username to identityKey to maintain address-based identity (casing normalized by CaipAccountId)
            String username = account.identityKey().toJwtSubject();

            KeycloakSession session = context.getSession();
            RealmModel realm = context.getRealm();
            UserModel user = session.users().getUserByUsername(realm, username);

            if (user == null) {
                user = session.users().addUser(realm, username);
                user.setEnabled(true);
                user.setAttribute("w3auth_address", List.of(parsed.address()));
                user.setAttribute("w3auth_namespace", List.of(namespace.name()));
                user.setAttribute("w3auth_chainId", List.of(parsed.chainId()));
            } else {
                // Guard against username pre-registration: a realm with self-registration
                // enabled lets an attacker create "eip155:0x<victim>" via the normal form
                // before the victim ever wallet-logs-in. Without this check a valid SIWE
                // from the victim silently binds to the attacker's account. Require the
                // wallet-binding attributes that this authenticator writes at first-provision.
                //
                // Explicit account linking (form-registered account → wallet) is out of
                // scope for V1. Do not add auto-claim logic here.
                String storedNamespace = user.getFirstAttribute("w3auth_namespace");
                String storedAddress   = user.getFirstAttribute("w3auth_address");
                boolean namespaceOk = namespace.name().equals(storedNamespace);
                // EVM addresses are case-insensitive (EIP-55 checksum casing varies across
                // wallets); Solana Base58 addresses are case-sensitive.
                boolean addressOk = (namespace == Namespace.SOLANA)
                        ? parsed.address().equals(storedAddress)
                        : parsed.address().equalsIgnoreCase(storedAddress);
                if (!namespaceOk || !addressOk) {
                    // Generic message: do not tell the client why the binding check failed
                    // (would reveal whether a pre-registered username collision exists).
                    context.challenge(buildLoginForm(context, "Authentication failed."));
                    return;
                }
            }

            context.setUser(user);
            context.getAuthenticationSession().removeAuthNote(NONCE_NOTE);
            context.success();

        } catch (Exception e) {
            context.challenge(buildLoginForm(context, "Wallet verification failed: " + e.getMessage()));
        }
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

    /**
     * Decodes the hex-encoded SIWE/SIWS message back to its canonical UTF-8 bytes.
     * Accepts an optional {@code 0x} prefix. Fail-closed on any malformed input:
     * odd length, empty, or a non-hex character.
     */
    private static String decodeHexMessage(String hex) {
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

    private static String getConfigValue(Map<String, String> config, String key, String defaultValue) {
        String val = config.get(key);
        return (val == null || val.isBlank()) ? defaultValue : val.trim();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
