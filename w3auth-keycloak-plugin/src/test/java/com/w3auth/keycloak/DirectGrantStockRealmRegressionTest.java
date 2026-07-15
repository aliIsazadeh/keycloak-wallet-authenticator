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
 * Regression test for the direct-grant path's counterpart to the stock-realm bug documented in
 * docs/investigation-stock-realm-required-actions.md. {@link StockRealmLoginRegressionTest} proved
 * the browser flow survives a plain-defaults realm; this proves the DIRECT-GRANT flow does too, on
 * the harsher no-recovery path: the spike (docs/spike-native-direct-grant.md) found that a bare
 * wallet-provisioned user tripping the declarative user-profile check gets a hard
 * {@code 400 "Account is not fully set up"} from the token endpoint, with no form to divert to.
 *
 * <p>{@link W3AuthDirectGrantIntegrationTest} defensively disables VERIFY_PROFILE / UPDATE_PROFILE /
 * update_profile_on_first_login at realm setup — exactly the kind of override that masked the
 * original stock-realm bug on the browser path. This test is that same integration test with ONLY
 * that override removed, to prove the v1.0.3 profile-completion fix (inherited via the shared
 * {@link W3AuthVerificationService} collaborator) actually satisfies the check here too, rather
 * than being assumed to.
 */
@Testcontainers
class DirectGrantStockRealmRegressionTest {

    // A freshly generated keypair, deliberately NOT the address used by
    // W3AuthDirectGrantIntegrationTest, so this exercises a first-time login (user == null
    // provisioning branch, where the profile-completion fix lives) rather than an
    // already-provisioned user hitting the else-branch. Generated (not hand-transcribed from a
    // well-known test vector) to avoid the single-hex-digit transcription error that class of
    // constant is prone to (see the M5 EIP-55 golden-vector journal entry for the same lesson).
    private static final String PRIVATE_KEY =
            "ff5a34907fe0d6803462f67c86c7c41aea198beeca82da3dcd54770e1633222b";
    private static final String EXPECTED_ADDRESS =
            "0x38f07f351900ffaac11c92d372394f9cb6060d64";

    private static final String REALM = "w3auth-direct-grant-stock-realm-test";
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
    private static Keycloak adminClient;

    @BeforeAll
    static void configureKeycloak() {
        serverUrl = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
        httpClient = HttpClient.newHttpClient();

        adminClient = KeycloakBuilder.builder()
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

        // DELIBERATELY OMITTED, unlike W3AuthDirectGrantIntegrationTest: disabling
        // VERIFY_PROFILE / UPDATE_PROFILE / update_profile_on_first_login. A stock realm never
        // gets that override either, and defensively adding it back here would mask the exact
        // gap this test exists to close. Do not "helpfully" re-add it.
    }

    @Test
    void directGrant_completesOnStockRealm_forFreshWalletUser() throws Exception {
        String accountId = "eip155:1:" + EXPECTED_ADDRESS;
        ChallengeResult challenge = requestChallenge(accountId);

        String signature = signPrefixed(challenge.rawMessage);
        HttpResponse<String> tokenResponse = requestToken(accountId, challenge.messageHex, signature);

        if (tokenResponse.statusCode() != 200) {
            System.err.println("Token request failed. Status: " + tokenResponse.statusCode());
            System.err.println("Body: " + tokenResponse.body());
        }
        assertThat(tokenResponse.statusCode())
                .as("a first-time wallet login on a stock (plain-defaults) realm must yield real "
                        + "Keycloak tokens, not the token endpoint's 400 \"Account is not fully set up\" "
                        + "that the spike hit for an incomplete declarative user profile")
                .isEqualTo(200);
        assertThat(tokenResponse.body()).contains("\"access_token\":\"");
        assertThat(tokenResponse.body()).contains("\"refresh_token\":\"");

        // Pin WHY it passed (the v1.0.3 profile-completion fix ran), not just THAT it passed:
        // the provisioned user must carry the address-derived placeholder profile fields that
        // satisfy Keycloak 25's default declarative user profile.
        String username = "eip155:" + EXPECTED_ADDRESS;
        List<UserRepresentation> users = adminClient.realm(REALM).users().search(username, true);
        assertThat(users)
                .as("the direct-grant authenticator must have provisioned a user for the fresh wallet")
                .hasSize(1);
        UserRepresentation provisionedUser = users.get(0);
        assertThat(provisionedUser.getFirstName()).isEqualTo("Wallet");
        assertThat(provisionedUser.getLastName()).isEqualTo(EXPECTED_ADDRESS);
        assertThat(provisionedUser.getEmail()).isEqualTo(EXPECTED_ADDRESS + "@wallet.invalid");
        assertThat(provisionedUser.isEmailVerified()).isTrue();
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
