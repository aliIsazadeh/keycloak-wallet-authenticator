package com.w3auth.keycloak;

import org.bouncycastle.math.ec.rfc8032.Ed25519;
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
 * Integration test for {@link W3AuthDirectGrantAuthenticator} on a SOLANA (SIWS) account — the
 * end-to-end native-path coverage gap left open by Slice B, which was EVM-only. Proves the locked
 * "SIWE and SIWS end-to-end" architecture decision holds on the direct-grant path, not just the
 * browser path ({@code W3AuthAuthenticatorIntegrationTest} covers SIWS there implicitly via the
 * shared collaborator, but the direct-grant flow's nonce handling, accountId cross-check, and
 * OAuth2 error mapping are its own code path and had zero SIWS exercise before this test).
 *
 * <p>Mirrors {@link W3AuthDirectGrantIntegrationTest}'s structure (one realm, a client-scoped
 * {@code direct_grant} flow override, happy path + replay + tamper) with the EVM signing swapped
 * for a real Ed25519 keypair and BouncyCastle signing — the same primitive
 * {@link com.w3auth.backend.verification.SolanaSignatureVerifier} verifies against.
 *
 * <p>The keypair below was generated programmatically (not hand-typed) and its address was
 * round-tripped through the exact base58 decode this project already ships
 * ({@code SolanaPublicKey.decode}) before being pinned here — see the project's recurring lesson
 * on hand-transcribed cryptographic constants (EIP-55 golden vectors, and this same slice's own
 * malformed-private-key bug in {@code DirectGrantStockRealmRegressionTest}).
 */
@Testcontainers
class DirectGrantSiwsIntegrationTest {

    // Ed25519 seed (32 bytes) — generated programmatically, not hand-transcribed.
    private static final String PRIVATE_KEY_HEX =
            "e55a7f053942bd3b6d6479f1ab009e0cad61d2b86e8f236c7c61d74ff9724cb3";
    // Base58-encoded Ed25519 public key derived from PRIVATE_KEY_HEX above, round-tripped through
    // SolanaPublicKey.decode before being pinned as a constant.
    private static final String SOLANA_ADDRESS =
            "BUwwQ7BenpZFVC6BVHMQSgEKWiFVGmJgVZwnAkVdYkXz";

    // CAIP-2 Solana mainnet reference — first 32 chars of the genesis hash, base58 (SolanaCluster.MAINNET).
    private static final String SOLANA_REFERENCE = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";

    private static final String REALM = "w3auth-direct-grant-siws-test";
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

        String flowId = adminClient.realm(REALM).flows().getFlows().stream()
                .filter(f -> FLOW_ALIAS.equals(f.getAlias()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("w3auth-direct-grant-flow not found after creation"))
                .getId();

        ClientRepresentation createdClient =
                adminClient.realm(REALM).clients().findByClientId(CLIENT_ID).get(0);
        createdClient.setAuthenticationFlowBindingOverrides(Map.of("direct_grant", flowId));
        adminClient.realm(REALM).clients().get(createdClient.getId()).update(createdClient);

        // Same v1.0.3 stock-realm profile-completion fix applies here via the shared collaborator;
        // this test isn't the stock-realm regression guard (that's DirectGrantStockRealmRegressionTest),
        // so disabling these required actions here is the same belt-and-braces posture as the
        // original DG integration test, not a gap.
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
    void directGrant_solanaHappyPath_thenReplay_thenTamper() throws Exception {
        // --- Happy path: challenge -> sign (Ed25519) -> token ---
        String accountId = "solana:" + SOLANA_REFERENCE + ":" + SOLANA_ADDRESS;
        ChallengeResult challenge = requestChallenge(accountId);

        String signature = signEd25519(challenge.rawMessage);
        HttpResponse<String> tokenResponse = requestToken(accountId, challenge.messageHex, signature);

        if (tokenResponse.statusCode() != 200) {
            System.err.println("Token request failed. Status: " + tokenResponse.statusCode());
            System.err.println("Body: " + tokenResponse.body());
        }
        assertThat(tokenResponse.statusCode())
                .as("a valid SIWS Ed25519 signature must yield real Keycloak tokens over the direct-grant path")
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
        String tamperedSignature = flipLastByte(signEd25519(freshChallenge.rawMessage));
        HttpResponse<String> tamperResponse = requestToken(accountId, freshChallenge.messageHex, tamperedSignature);
        assertThat(tamperResponse.statusCode())
                .as("a tampered Ed25519 signature must not verify")
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

    /**
     * Signs {@code message} with the fixed Ed25519 seed via BouncyCastle's low-level RFC 8032
     * implementation — the exact primitive {@code SolanaSignatureVerifier} verifies against
     * (see its {@code Ed25519.verify} call), so this is a genuine round-trip, not a parallel
     * reimplementation.
     */
    private static String signEd25519(String message) {
        byte[] privateKey = hexToBytes(PRIVATE_KEY_HEX);
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] signature = new byte[Ed25519.SIGNATURE_SIZE];
        Ed25519.sign(privateKey, 0, messageBytes, 0, messageBytes.length, signature, 0);
        return toHexNoPrefix(signature);
    }

    private static String toHexNoPrefix(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
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
