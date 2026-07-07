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
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

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
        String nonce = Nonce.generate();
        context.getAuthenticationSession().setAuthNote(NONCE_NOTE, nonce);

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        Map<String, String> configMap = config != null ? config.getConfig() : Map.of();
        String expectedDomain = configMap.getOrDefault("expected-domain", "localhost");
        String expectedUri = configMap.getOrDefault("expected-uri", "http://localhost:8080");

        Response challengeForm = context.form()
                .setAttribute("nonce", nonce)
                .setAttribute("expectedDomain", expectedDomain)
                .setAttribute("expectedUri", expectedUri)
                .createForm("w3auth-login.ftl");
        context.challenge(challengeForm);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String accountIdStr = formData.getFirst("accountId");
        String rawMessage = formData.getFirst("message");
        String signature = formData.getFirst("signature");

        if (accountIdStr == null || rawMessage == null || signature == null ||
                accountIdStr.isBlank() || rawMessage.isBlank() || signature.isBlank()) {
            Response errorForm = context.form()
                    .setError("Missing wallet login credentials")
                    .createForm("w3auth-login.ftl");
            context.challenge(errorForm);
            return;
        }

        String storedNonce = context.getAuthenticationSession().getAuthNote(NONCE_NOTE);
        if (storedNonce == null) {
            Response errorForm = context.form()
                    .setError("Login session expired. Please reload.")
                    .createForm("w3auth-login.ftl");
            context.challenge(errorForm);
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
            String expectedDomain = configMap.getOrDefault("expected-domain", "localhost");
            String expectedUri = configMap.getOrDefault("expected-uri", "http://localhost:8080");
            String rpcUrl = configMap.get("ethereum-rpc-url");

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
            }

            context.setUser(user);
            context.getAuthenticationSession().removeAuthNote(NONCE_NOTE);
            context.success();

        } catch (Exception e) {
            Response errorForm = context.form()
                    .setError("Wallet verification failed: " + e.getMessage())
                    .createForm("w3auth-login.ftl");
            context.challenge(errorForm);
        }
    }

    private static Namespace detectNamespace(String rawMessage) {
        if (rawMessage == null) {
            throw new IllegalArgumentException("message must not be null");
        }
        int firstNewLine = rawMessage.indexOf('\n');
        String firstLine = (firstNewLine == -1) ? rawMessage : rawMessage.substring(0, firstNewLine);
        if (firstLine.endsWith(" wants you to sign in with your Ethereum account:")) {
            return Namespace.EIP155;
        } else if (firstLine.endsWith(" wants you to sign in with your Solana account:")) {
            return Namespace.SOLANA;
        }
        throw new IllegalArgumentException("Unknown or unsupported authentication message format");
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
