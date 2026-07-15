package com.w3auth.keycloak;

import com.w3auth.backend.challenge.Challenge;
import com.w3auth.backend.challenge.Nonce;
import com.w3auth.backend.challenge.SiweMessageFactory;
import com.w3auth.backend.challenge.SiwsMessageFactory;
import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.services.resource.RealmResourceProvider;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Unauthenticated realm resource that issues server-built SIWE/SIWS challenge messages.
 *
 * <p>Routes (base path {@code /realms/{realm}/w3auth/}):
 * <ul>
 *   <li>{@code POST challenge} — issue a challenge for the given CAIP-10 account id.</li>
 * </ul>
 *
 * <h2>Domain / URI configuration</h2>
 * A {@code RealmResourceProvider} has no {@code AuthenticatorConfigModel} context — it is not
 * bound to any flow execution. Realm attributes are the only config surface reachable from
 * a realm resource endpoint, and they support per-realm operator customization via the admin
 * API. Set {@code w3auth.expected-domain} and {@code w3auth.expected-uri} on the realm.
 *
 * <p>For native clients, {@code w3auth.expected-domain} is the app's declared metadata
 * domain (e.g. the universal-link domain in the Apple App Site Association file), not the
 * Keycloak host. Wallets bind the SIWE domain field to the app's registered domain, not
 * the server that issued the challenge.
 *
 * <h2>Rate limiting</h2>
 * The 300-second nonce TTL bounds the maximum outstanding challenge window per nonce.
 * In-process per-IP rate limiting is not built here (rule of three — no second concrete
 * demand yet). Operators SHOULD rate-limit {@code POST /realms/{realm}/w3auth/challenge}
 * at the reverse proxy (e.g. nginx {@code limit_req}).
 */
public class W3AuthChallengeResourceProvider implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(W3AuthChallengeResourceProvider.class);

    static final long NONCE_TTL_SECONDS = 300L;
    static final String NONCE_KEY_PREFIX = "w3auth.nonce.";

    // Realm-attribute keys — the only config surface for this unauthenticated resource (no
    // AuthenticatorConfigModel context). W3AuthDirectGrantAuthenticator reads the SAME keys via
    // realmAttr() below so a message this endpoint builds and the direct-grant authenticator that
    // verifies it always agree on expected domain/uri — see STEP 3 in the v1.1 direct-grant plan.
    static final String REALM_ATTR_DOMAIN = "w3auth.expected-domain";
    static final String REALM_ATTR_URI = "w3auth.expected-uri";

    static final String DEFAULT_DOMAIN = "localhost";
    static final String DEFAULT_URI = "http://localhost:8080";

    private final KeycloakSession session;

    W3AuthChallengeResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    /**
     * Issues a server-built SIWE or SIWS challenge message.
     *
     * <p>Request body (JSON): {@code { "accountId": "<CAIP-10>", "clientId": "<optional>" }}.
     *
     * <p>Response (JSON):
     * <pre>{@code { "messageHex": "<hex of UTF-8 message bytes>", "nonce": "<nonce>", "expiresAt": "<ISO-8601>" }}</pre>
     *
     * <p>{@code messageHex} is the hex-encoding of the exact UTF-8 bytes of the message — the
     * same byte-exact discipline the browser flow uses. Clients MUST NOT modify or re-encode
     * the bytes before presenting them to the wallet for signing (the wallet signs over exactly
     * these bytes, and the verification path hashes exactly these bytes).
     */
    @POST
    @Path("challenge")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response challenge(String body) {
        if (body == null || body.isBlank()) {
            return badRequest();
        }

        String accountIdStr = extractJsonString(body, "accountId");
        String clientId = extractJsonString(body, "clientId");

        if (accountIdStr == null || accountIdStr.isBlank()) {
            return badRequest();
        }

        CaipAccountId account;
        try {
            account = CaipAccountId.parse(accountIdStr);
        } catch (IllegalArgumentException e) {
            // No detail in the response — no internal structure leak.
            logger.debugf("w3auth challenge: rejected malformed accountId: %.200s", e.getMessage());
            return badRequest();
        }

        RealmModel realm = session.getContext().getRealm();
        String domain = realmAttr(realm, REALM_ATTR_DOMAIN, DEFAULT_DOMAIN);
        String uri = realmAttr(realm, REALM_ATTR_URI, DEFAULT_URI);

        String nonce = Nonce.generate();
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(NONCE_TTL_SECONDS);

        Challenge challenge = new Challenge(account, nonce, domain, uri, issuedAt, expiresAt);

        String message;
        try {
            message = switch (account.namespace()) {
                case EIP155 -> SiweMessageFactory.create(challenge);
                case SOLANA -> SiwsMessageFactory.create(challenge);
            };
        } catch (IllegalArgumentException e) {
            logger.debugf("w3auth challenge: message construction failed: %.200s", e.getMessage());
            return badRequest();
        }

        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        String messageHex = HexFormat.of().formatHex(messageBytes);

        // Store nonce for atomic single-use consumption at verify time (Slice B uses remove()).
        // notes carries context for Slice B's VerifyAndAuthenticate logic.
        Map<String, String> notes = Map.of(
                "accountId", account.toString(),
                "clientId", clientId != null ? clientId : "",
                "issuedAt", issuedAt.toString()
        );
        session.getProvider(SingleUseObjectProvider.class)
               .put(NONCE_KEY_PREFIX + nonce, NONCE_TTL_SECONDS, notes);

        return Response.ok(buildResponseJson(messageHex, nonce, expiresAt.toString()),
                           MediaType.APPLICATION_JSON).build();
    }

    @Override
    public void close() {
    }

    // --- helpers ---

    static String realmAttr(RealmModel realm, String key, String defaultValue) {
        String val = realm.getAttribute(key);
        return (val == null || val.isBlank()) ? defaultValue : val.trim();
    }

    private static Response badRequest() {
        return Response.status(Response.Status.BAD_REQUEST)
                       .entity("{\"error\":\"invalid_request\"}")
                       .type(MediaType.APPLICATION_JSON)
                       .build();
    }

    // All response values are controlled (hex, hex, ISO-8601) — no JSON metacharacters possible.
    private static String buildResponseJson(String messageHex, String nonce, String expiresAt) {
        return "{\"messageHex\":\"" + messageHex
               + "\",\"nonce\":\"" + nonce
               + "\",\"expiresAt\":\"" + expiresAt + "\"}";
    }

    /**
     * Extracts a string value from a JSON object for the given field name.
     * Handles the two controlled fields this endpoint reads ({@code accountId},
     * {@code clientId}): plain ASCII, no embedded quotes or backslashes expected.
     * Returns {@code null} if the field is absent.
     */
    private static String extractJsonString(String json, String field) {
        Matcher m = Pattern.compile(
                "\"" + Pattern.quote(field) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"")
                .matcher(json);
        return m.find() ? m.group(1) : null;
    }
}
