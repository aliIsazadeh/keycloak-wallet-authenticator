package com.w3auth.keycloak;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.*;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for {@link W3AuthDirectGrantAuthenticator}: a native app POSTs
 * {@code grant_type=password} with a wallet signature straight to the OIDC token endpoint and
 * gets real Keycloak-issued tokens — no browser round-trip.
 *
 * <p>Wires a client-scoped {@code direct_grant} flow override per the spike's Q3 finding
 * (docs/spike-native-direct-grant.md): a custom flow whose single execution is
 * {@code w3auth-direct-grant-authenticator}, bound via
 * {@code ClientRepresentation.authenticationFlowBindingOverrides}. Other clients and the realm's
 * default {@code direct grant} flow are unaffected.
 *
 * <p>Scope: EVM happy path + replay + tamper. SIWS end-to-end, smart-wallet, and the full
 * contract-test matrix are Slice C.
 */
@Testcontainers
class W3AuthDirectGrantIntegrationTest {

    private static final String PRIVATE_KEY =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    private static final String EXPECTED_ADDRESS =
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

    private static final String REALM = "w3auth-direct-grant-test";
    private static final String CLIENT_ID = "native-test-client";
    private static final String FLOW_ALIAS = "w3auth-direct-grant-flow";

    private static final String EXPECTED_DOMAIN = "localhost";
    private static final String EXPECTED_URI = "http://localhost:8080";

    @Container
    private static final GenericContainer<?> keycloak = new GenericContainer<>(
            DockerImageName.parse("quay.io/keycloak/keycloak:25.0.2"))
            .withExposedPorts(8080)
            .withEnv("KEYCLOAK_ADMIN", "admin")
            .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
            .withCommand("start-dev")
            .withFileSystemBind(
                    System.getProperty("plugin.jar.path"),
                    "/opt/keycloak/providers/w3auth-plugin.jar",
                    BindMode.READ_ONLY)
            .waitingFor(Wait.forHttp("/realms/master").forStatusCode(200));

    private static String serverUrl;
    private static HttpClient httpClient;

    @BeforeAll
    static void configureKeycloak() {
        serverUrl = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
        httpClient = HttpClient.newHttpClient();

        Keycloak adminClient = KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm("master")
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build();

        RealmRepresentation realmRep = new RealmRepresentation();
        realmRep.setRealm(REALM);
        realmRep.setEnabled(true);
        // Same realm attributes the challenge endpoint reads to build the message — the
        // direct-grant authenticator MUST validate against these, not AuthenticatorConfig.
        realmRep.setAttributes(Map.of(
                "w3auth.expected-domain", EXPECTED_DOMAIN,
                "w3auth.expected-uri", EXPECTED_URI
        ));

        ClientRepresentation clientRep = new ClientRepresentation();
        clientRep.setClientId(CLIENT_ID);
        clientRep.setEnabled(true);
        clientRep.setPublicClient(true);
        clientRep.setDirectAccessGrantsEnabled(true);
        realmRep.setClients(List.of(clientRep));

        adminClient.realms().create(realmRep);

        // A direct_grant-only flow with exactly one execution: our authenticator. No
        // username/password validators present at all (per spike Q3 — not bypassed, absent).
        AuthenticationFlowRepresentation flow = new AuthenticationFlowRepresentation();
        flow.setAlias(FLOW_ALIAS);
        flow.setProviderId("basic-flow");
        flow.setDescription("Native wallet direct-grant login flow");
        flow.setTopLevel(true);
        flow.setBuiltIn(false);
        adminClient.realm(REALM).flows().createFlow(flow);

        Map<String, Object> executionData = new HashMap<>();
        executionData.put("provider", "w3auth-direct-grant-authenticator");
        adminClient.realm(REALM).flows().addExecution(FLOW_ALIAS, executionData);

        List<AuthenticationExecutionInfoRepresentation> executions =
                adminClient.realm(REALM).flows().getExecutions(FLOW_ALIAS);
        AuthenticationExecutionInfoRepresentation execution = executions.stream()
                .filter(e -> "w3auth-direct-grant-authenticator".equals(e.getProviderId()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("w3auth-direct-grant-authenticator execution not found"));
        execution.setRequirement("REQUIRED");
        adminClient.realm(REALM).flows().updateExecutions(FLOW_ALIAS, execution);

        // Client-scoped override — the realm's default "direct grant" flow (and other clients)
        // is untouched.
        String flowId = adminClient.realm(REALM).flows().getFlows().stream()
                .filter(f -> FLOW_ALIAS.equals(f.getAlias()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("w3auth-direct-grant-flow not found after creation"))
                .getId();

        ClientRepresentation createdClient =
                adminClient.realm(REALM).clients().findByClientId(CLIENT_ID).get(0);
        createdClient.setAuthenticationFlowBindingOverrides(Map.of("direct_grant", flowId));
        adminClient.realm(REALM).clients().get(createdClient.getId()).update(createdClient);

        // The spike's one real gotcha: a bare wallet-provisioned user trips Keycloak 25's
        // declarative user-profile UPDATE_PROFILE required action, and the token endpoint
        // refuses to issue tokens while a required action is pending — regardless of what the
        // auth flow decided. W3AuthVerificationService already sets firstName/lastName/email at
        // provision time (the v1.0.3 stock-realm fix, inherited via the shared collaborator), so
        // this is redundant belt-and-braces consistent with the other integration tests, not a
        // workaround for a gap in the authenticator itself.
        adminClient.realm(REALM).flows().getRequiredActions().forEach(action -> {
            if ("VERIFY_PROFILE".equals(action.getAlias())
                    || "UPDATE_PROFILE".equals(action.getAlias())
                    || "update_profile_on_first_login".equals(action.getAlias())) {
                action.setEnabled(false);
                adminClient.realm(REALM).flows().updateRequiredAction(action.getAlias(), action);
            }
        });
    }

    @Test
    void directGrant_evmHappyPath_thenReplay_thenTamper() throws Exception {
        // --- Happy path: challenge -> sign -> token ---
        String accountId = "eip155:1:" + EXPECTED_ADDRESS;
        ChallengeResult challenge = requestChallenge(accountId);

        String signature = signPrefixed(challenge.rawMessage);
        HttpResponse<String> tokenResponse = requestToken(accountId, challenge.messageHex, signature);

        if (tokenResponse.statusCode() != 200) {
            System.err.println("Token request failed. Status: " + tokenResponse.statusCode());
            System.err.println("Body: " + tokenResponse.body());
        }
        assertThat(tokenResponse.statusCode())
                .as("a valid wallet signature must yield real Keycloak tokens")
                .isEqualTo(200);
        assertThat(tokenResponse.body()).contains("\"access_token\":\"");
        assertThat(tokenResponse.body()).contains("\"refresh_token\":\"");

        // --- Replay: the exact same request again must fail (nonce already consumed) ---
        HttpResponse<String> replayResponse = requestToken(accountId, challenge.messageHex, signature);
        assertThat(replayResponse.statusCode())
                .as("replaying a consumed nonce must not succeed")
                .isNotEqualTo(200);
        assertThat(replayResponse.body())
                .as("replay must be rejected as a generic invalid_grant")
                .contains("invalid_grant");

        // --- Tamper: a fresh challenge, signature flipped by one byte ---
        ChallengeResult freshChallenge = requestChallenge(accountId);
        String tamperedSignature = flipLastByte(signPrefixed(freshChallenge.rawMessage));
        HttpResponse<String> tamperResponse = requestToken(accountId, freshChallenge.messageHex, tamperedSignature);
        assertThat(tamperResponse.statusCode())
                .as("a tampered signature must not verify")
                .isNotEqualTo(200);
        assertThat(tamperResponse.body())
                .as("tamper must be rejected as a generic invalid_grant")
                .contains("invalid_grant");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private record ChallengeResult(String messageHex, String rawMessage) {
    }

    private ChallengeResult requestChallenge(String accountId) throws Exception {
        HttpResponse<String> resp = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(serverUrl + "/realms/" + REALM + "/w3auth/challenge"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString("{\"accountId\":\"" + accountId + "\"}"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(resp.statusCode()).as("challenge request must succeed, body: %s", resp.body()).isEqualTo(200);

        String messageHex = extractJson(resp.body(), "messageHex");
        assertThat(messageHex).isNotBlank();
        String rawMessage = new String(hexToBytes(messageHex), StandardCharsets.UTF_8);
        return new ChallengeResult(messageHex, rawMessage);
    }

    private HttpResponse<String> requestToken(String accountId, String messageHex, String signature) throws Exception {
        String postBody = "grant_type=password"
                + "&client_id=" + URLEncoder.encode(CLIENT_ID, StandardCharsets.UTF_8)
                + "&w3auth_account_id=" + URLEncoder.encode(accountId, StandardCharsets.UTF_8)
                + "&w3auth_message_hex=" + URLEncoder.encode(messageHex, StandardCharsets.UTF_8)
                + "&w3auth_signature=" + URLEncoder.encode(signature, StandardCharsets.UTF_8);

        return httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(serverUrl + "/realms/" + REALM + "/protocol/openid-connect/token"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(postBody))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String signPrefixed(String message) {
        ECKeyPair keyPair = ECKeyPair.create(Numeric.hexStringToByteArray(PRIVATE_KEY));
        Sign.SignatureData sigData = Sign.signPrefixedMessage(message.getBytes(StandardCharsets.UTF_8), keyPair);
        byte[] sigBytes = new byte[65];
        System.arraycopy(sigData.getR(), 0, sigBytes, 0, 32);
        System.arraycopy(sigData.getS(), 0, sigBytes, 32, 32);
        sigBytes[64] = sigData.getV()[0];
        return "0x" + Numeric.toHexStringNoPrefix(sigBytes);
    }

    private static String flipLastByte(String hexSignature) {
        String prefix = hexSignature.substring(0, hexSignature.length() - 2);
        String lastByte = hexSignature.substring(hexSignature.length() - 2);
        int value = Integer.parseInt(lastByte, 16) ^ 0xFF;
        return prefix + String.format("%02x", value);
    }

    private static String extractJson(String json, String field) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\"([^\"]+)\"")
                           .matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static byte[] hexToBytes(String hex) {
        String clean = hex.startsWith("0x") ? hex.substring(2) : hex;
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
