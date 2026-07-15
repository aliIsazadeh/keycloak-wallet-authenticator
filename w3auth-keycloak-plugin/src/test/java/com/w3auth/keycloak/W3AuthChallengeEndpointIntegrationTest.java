package com.w3auth.keycloak;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.RealmRepresentation;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@link W3AuthChallengeResourceProvider}.
 *
 * <p>Verifies the unauthenticated {@code POST /realms/{realm}/w3auth/challenge} endpoint against
 * a live Keycloak 25.0.2 container (same image as {@link W3AuthAuthenticatorIntegrationTest}).
 */
@Testcontainers
class W3AuthChallengeEndpointIntegrationTest {

    private static final String REALM = "w3auth-challenge-test";

    // Standard Foundry/Hardhat test account 0 — lowercase for CAIP-10 input, checksummed for assertions.
    private static final String EVM_ADDRESS_LOWER = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    // EIP-55 checksummed form of the address above. Verified independently of web3j via the
    // js-sha3 (npm) reference Keccak-256 implementation, and matches the well-known Hardhat/Anvil
    // default account #0 casing published in Hardhat/Foundry's own docs and node startup output.
    private static final String EVM_ADDRESS_CHECKSUMMED = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    // RFC 8032 §7.1 TEST 2 public key in base58 — valid 32-byte Solana address (verified in SolanaSignatureVerifierTest).
    private static final String SOLANA_ADDRESS = "586Z7H2vpX9qNhN2T4e9Utugie3ogjbxzGaMtM3E6HR5";
    // Solana mainnet CAIP-2 reference (first 32 chars of mainnet genesis hash).
    private static final String SOLANA_REFERENCE = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";

    private static final String EXPECTED_DOMAIN = "localhost";
    private static final String EXPECTED_URI    = "http://localhost:8080";

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
        // Realm attributes are the config surface for RealmResourceProvider (no AuthenticatorConfig context).
        realmRep.setAttributes(Map.of(
                "w3auth.expected-domain", EXPECTED_DOMAIN,
                "w3auth.expected-uri", EXPECTED_URI
        ));
        adminClient.realms().create(realmRep);
    }

    // -------------------------------------------------------------------------
    // EVM (EIP-155) — SIWE message with EIP-55 checksummed address
    // -------------------------------------------------------------------------

    @Test
    void postChallenge_validEvmAccountId_returnsSiweMessageWithChecksummedAddress() throws Exception {
        String accountId = "eip155:1:" + EVM_ADDRESS_LOWER;
        String responseBody = postChallenge(accountId);

        assertThat(extractJson(responseBody, "nonce")).matches("[0-9a-f]{32}");
        assertThat(extractJson(responseBody, "expiresAt")).isNotBlank();

        String messageHex = extractJson(responseBody, "messageHex");
        assertThat(messageHex).isNotBlank();

        String message = new String(hexToBytes(messageHex), StandardCharsets.UTF_8);

        // Valid SIWE first line
        assertThat(message).startsWith(EXPECTED_DOMAIN + " wants you to sign in with your Ethereum account:");

        // Address line must be EIP-55 checksummed — lowercase form rejected by strict wallets
        String[] lines = message.split("\n", -1);
        assertThat(lines[1]).isEqualTo(EVM_ADDRESS_CHECKSUMMED);

        // Nonce in message must match the nonce field in the response
        String nonce = extractJson(responseBody, "nonce");
        assertThat(message).contains("Nonce: " + nonce);

        // Domain must be the realm-configured value (not the Keycloak host)
        assertThat(message).contains("URI: " + EXPECTED_URI);
    }

    // -------------------------------------------------------------------------
    // Solana — SIWS message, no EIP-55 applied
    // -------------------------------------------------------------------------

    @Test
    void postChallenge_validSolanaAccountId_returnsSiwsMessage() throws Exception {
        String accountId = "solana:" + SOLANA_REFERENCE + ":" + SOLANA_ADDRESS;
        String responseBody = postChallenge(accountId);

        assertThat(extractJson(responseBody, "nonce")).matches("[0-9a-f]{32}");

        String message = new String(hexToBytes(extractJson(responseBody, "messageHex")), StandardCharsets.UTF_8);

        // Valid SIWS first line
        assertThat(message).startsWith(EXPECTED_DOMAIN + " wants you to sign in with your Solana account:");

        // Solana address appears exactly as-is — base58 is case-sensitive, no EIP-55 applied
        assertThat(message).contains(SOLANA_ADDRESS);

        // Cluster name for mainnet genesis hash
        assertThat(message).contains("Chain ID: mainnet");
    }

    // -------------------------------------------------------------------------
    // Malformed input — generic 400, no detail leak
    // -------------------------------------------------------------------------

    @Test
    void postChallenge_malformedAccountId_returns400() throws Exception {
        HttpResponse<String> resp = postChallengeRaw("{\"accountId\":\"not-a-caip10\"}");
        assertThat(resp.statusCode()).isEqualTo(400);
        assertThat(resp.body()).doesNotContain("not-a-caip10");
        assertThat(resp.body()).contains("invalid_request");
    }

    @Test
    void postChallenge_missingAccountId_returns400() throws Exception {
        HttpResponse<String> resp = postChallengeRaw("{\"clientId\":\"some-client\"}");
        assertThat(resp.statusCode()).isEqualTo(400);
    }

    @Test
    void postChallenge_emptyBody_returns400() throws Exception {
        HttpResponse<String> resp = postChallengeRaw("");
        assertThat(resp.statusCode()).isEqualTo(400);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private String postChallenge(String accountId) throws Exception {
        HttpResponse<String> resp = postChallengeRaw(
                "{\"accountId\":\"" + accountId + "\"}");
        assertThat(resp.statusCode())
                .as("expected 200 for accountId: %s, body: %s", accountId, resp.body())
                .isEqualTo(200);
        return resp.body();
    }

    private HttpResponse<String> postChallengeRaw(String body) throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(serverUrl + "/realms/" + REALM + "/w3auth/challenge"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String extractJson(String json, String field) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\"([^\"]+)\"")
                           .matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
