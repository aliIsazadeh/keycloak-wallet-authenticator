package com.w3auth.keycloak;

import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.verification.AuthMessage;
import com.w3auth.backend.verification.VerificationException;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;

import java.util.Map;

/**
 * Keycloak Authenticator for a native {@code direct_grant} flow: a client POSTs
 * {@code grant_type=password} to the OIDC token endpoint carrying a wallet signature instead of a
 * username/password, and — on success — receives real Keycloak-issued tokens with no browser
 * round-trip.
 *
 * <p>Shares all SIWE/SIWS verification and user-provisioning logic with the browser authenticator
 * ({@link W3AuthAuthenticator}) via {@link W3AuthVerificationService}. What differs from the
 * browser flow, by design:
 * <ul>
 *   <li><b>Nonce store</b> — the browser flow keeps its nonce in the Keycloak auth-session note;
 *       this flow has no session to carry a note across a redirect, so it consumes the nonce
 *       Slice A's challenge endpoint stored via {@link SingleUseObjectProvider}, atomically
 *       ({@code remove()} — GETDEL-equivalent) so a replayed token request can never reuse a
 *       consumed nonce.</li>
 *   <li><b>Config source</b> — domain/uri are read from the SAME realm attributes
 *       ({@code w3auth.expected-domain} / {@code w3auth.expected-uri}) the challenge endpoint used
 *       to build the message, via {@link W3AuthChallengeResourceProvider#realmAttr}. A
 *       {@code RealmResourceProvider} (the challenge endpoint) has no
 *       {@code AuthenticatorConfigModel} context, so realm attributes are the only config surface
 *       both sides can agree on. rpcUrl is read the same way, from
 *       {@code w3auth.ethereum-rpc-url}.</li>
 *   <li><b>Failure translation</b> — every rejection reason (missing fields, malformed hex,
 *       nonce missing/expired/consumed, account mismatch, domain/uri/expiry mismatch, bad
 *       signature, signer mismatch, pre-registration collision) maps to the SAME generic
 *       {@code invalid_grant} via {@link AuthenticationFlowError#INVALID_CREDENTIALS}. Unlike the
 *       browser flow, there is no form to re-render with a tailored message, and revealing which
 *       specific check failed would be an oracle for an attacker probing account existence or
 *       nonce validity.</li>
 * </ul>
 */
public class W3AuthDirectGrantAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(W3AuthDirectGrantAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        action(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String accountIdStr = formData.getFirst("w3auth_account_id");
        String messageHex = formData.getFirst("w3auth_message_hex");
        String signature = formData.getFirst("w3auth_signature");

        if (accountIdStr == null || messageHex == null || signature == null ||
                accountIdStr.isBlank() || messageHex.isBlank() || signature.isBlank()) {
            reject(context, "missing required w3auth_ form fields");
            return;
        }

        String rawMessage;
        try {
            rawMessage = W3AuthVerificationService.decodeHexMessage(messageHex);
        } catch (IllegalArgumentException e) {
            reject(context, "malformed message hex");
            return;
        }

        try {
            AuthMessage parsed = W3AuthVerificationService.parseMessage(rawMessage);

            KeycloakSession session = context.getSession();
            Map<String, String> notes = session.getProvider(SingleUseObjectProvider.class)
                    .remove(W3AuthChallengeResourceProvider.NONCE_KEY_PREFIX + parsed.nonce());
            if (notes == null) {
                // Missing, expired, or already consumed — this IS the replay defense.
                reject(context, "nonce missing, expired, or already consumed");
                return;
            }

            String storedAccountId = notes.get("accountId");
            CaipAccountId derivedAccount = W3AuthVerificationService.deriveAccount(parsed);
            boolean accountMatches = storedAccountId != null
                    && storedAccountId.equals(derivedAccount.toString())
                    && storedAccountId.equals(accountIdStr);
            if (!accountMatches) {
                reject(context, "submitted accountId does not match the account the nonce was issued for");
                return;
            }

            RealmModel realm = context.getRealm();
            String expectedDomain = W3AuthChallengeResourceProvider.realmAttr(
                    realm, W3AuthChallengeResourceProvider.REALM_ATTR_DOMAIN, W3AuthChallengeResourceProvider.DEFAULT_DOMAIN);
            String expectedUri = W3AuthChallengeResourceProvider.realmAttr(
                    realm, W3AuthChallengeResourceProvider.REALM_ATTR_URI, W3AuthChallengeResourceProvider.DEFAULT_URI);
            String rpcUrl = W3AuthChallengeResourceProvider.realmAttr(realm, "w3auth.ethereum-rpc-url", null);

            W3AuthVerificationService.VerifiedLogin result = W3AuthVerificationService.verifyAndProvision(
                    session, realm, parsed, rawMessage, signature, expectedDomain, expectedUri, rpcUrl);

            context.setUser(result.user());
            context.success();

        } catch (VerificationException | IllegalArgumentException e) {
            // Log the detail server-side only (truncated). Never log the raw signature,
            // decoded message, or messageHex — matches the browser authenticator's discipline.
            logger.warnf("w3auth-direct-grant: auth rejected [%s]: %.500s",
                    e.getClass().getSimpleName(),
                    e.getMessage() != null ? e.getMessage() : "");
            reject(context, "verification failed");
        } catch (Exception e) {
            logger.warn("w3auth-direct-grant: unexpected verification error: " + e.getClass().getName(), e);
            reject(context, "unexpected error");
        }
    }

    /**
     * Fails the flow with a single generic {@code invalid_grant} OAuth2 error, regardless of
     * {@code reason} — no oracle. {@code reason} is for the caller's own clarity at the call site
     * only; it is never logged or sent to the client. Builds the error body explicitly (mirroring
     * Keycloak's own {@code direct-grant-validate-password}) rather than relying on
     * {@code context.failure}'s default mapping, so the token endpoint reliably returns
     * {@code invalid_grant} and not some other OAuth2 error code.
     */
    private static void reject(AuthenticationFlowContext context, String reason) {
        OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation("invalid_grant", "Invalid wallet credentials");
        Response challengeResponse = Response.status(Response.Status.UNAUTHORIZED)
                .entity(errorRep)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
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
