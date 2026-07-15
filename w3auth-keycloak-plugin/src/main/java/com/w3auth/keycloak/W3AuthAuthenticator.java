package com.w3auth.keycloak;

import com.w3auth.backend.challenge.Nonce;
import com.w3auth.backend.verification.AuthMessage;
import com.w3auth.backend.verification.VerificationException;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Map;

/**
 * Custom Keycloak Authenticator that validates Web3 signatures (SIWE/SIWS)
 * and provisions or logs in a corresponding Keycloak user.
 */
public class W3AuthAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(W3AuthAuthenticator.class);
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
            rawMessage = W3AuthVerificationService.decodeHexMessage(messageHex);
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
            AuthMessage parsed = W3AuthVerificationService.parseMessage(rawMessage);

            if (!storedNonce.equals(parsed.nonce())) {
                throw new VerificationException("Nonce mismatch. Potential replay attack.");
            }

            AuthenticatorConfigModel config = context.getAuthenticatorConfig();
            Map<String, String> configMap = config != null ? config.getConfig() : Map.of();
            String expectedDomain = getConfigValue(configMap, "expected-domain", "localhost");
            String expectedUri = getConfigValue(configMap, "expected-uri", "http://localhost:8080");
            String rpcUrl = getConfigValue(configMap, "ethereum-rpc-url", null);

            W3AuthVerificationService.VerifiedLogin result = W3AuthVerificationService.verifyAndProvision(
                    context.getSession(), context.getRealm(), parsed, rawMessage, signature,
                    expectedDomain, expectedUri, rpcUrl);

            context.setUser(result.user());
            context.getAuthenticationSession().removeAuthNote(NONCE_NOTE);
            context.success();

        } catch (W3AuthVerificationService.BindingConflictException e) {
            context.challenge(buildLoginForm(context, "Authentication failed."));
        } catch (VerificationException | IllegalArgumentException e) {
            // Log the detail server-side (truncated — message may contain client-derived content).
            // Never include the raw signature, decoded message, or messageHex in logs.
            logger.warnf("w3auth: auth rejected [%s]: %.500s",
                    e.getClass().getSimpleName(),
                    e.getMessage() != null ? e.getMessage() : "");
            context.challenge(buildLoginForm(context, "Wallet verification failed. Please try again."));
        } catch (Exception e) {
            // Unexpected error (NullPointerException, IO failure, etc.): log with stack trace.
            logger.warn("w3auth: unexpected verification error: " + e.getClass().getName(), e);
            context.challenge(buildLoginForm(context, "Wallet verification failed. Please try again."));
        }
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
