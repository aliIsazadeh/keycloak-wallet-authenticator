package com.w3auth.keycloak;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.*;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.containers.wait.strategy.Wait;
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
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression test for the stock-realm required-action bug documented in
 * docs/investigation-stock-realm-required-actions.md: on a Keycloak 25 realm created
 * with plain defaults (no required-action tweaks), the browser flow must still complete
 * login after a valid wallet signature — not divert to a VERIFY_PROFILE
 * "Update Account Information" page.
 *
 * <p>Deliberately does NOT disable any required actions at the realm level (unlike
 * {@link W3AuthAuthenticatorIntegrationTest}) — that is the entire point: this proves the
 * plugin works out of the box on a realm an operator never touched.
 */
@Testcontainers
class StockRealmLoginRegressionTest {

    private static final String PRIVATE_KEY =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    private static final String EXPECTED_ADDRESS =
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    private static final String REALM = "stock-realm";

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
    static void setupStockRealm() {
        serverUrl = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
        httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .cookieHandler(new java.net.CookieManager())
                .build();

        Keycloak adminClient = KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm("master")
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build();

        // Realm created with Keycloak's plain defaults — no userProfile config, no
        // required-action overrides. This is what a self-hoster gets from a bare
        // `createRealm` call or the admin console's "Create realm" with no extra steps.
        RealmRepresentation realmRep = new RealmRepresentation();
        realmRep.setRealm(REALM);
        realmRep.setEnabled(true);

        ClientRepresentation clientRep = new ClientRepresentation();
        clientRep.setClientId("test-app");
        clientRep.setEnabled(true);
        clientRep.setRedirectUris(List.of("http://localhost:8080/callback"));
        clientRep.setPublicClient(true);
        clientRep.setDirectAccessGrantsEnabled(true);
        realmRep.setClients(List.of(clientRep));

        adminClient.realms().create(realmRep);

        AuthenticationFlowRepresentation flow = new AuthenticationFlowRepresentation();
        flow.setAlias("w3auth-flow");
        flow.setProviderId("basic-flow");
        flow.setDescription("Web3 Wallet Signature Login Flow");
        flow.setTopLevel(true);
        flow.setBuiltIn(false);
        adminClient.realm(REALM).flows().createFlow(flow);

        Map<String, Object> executionData = new HashMap<>();
        executionData.put("provider", "w3auth-authenticator");
        adminClient.realm(REALM).flows().addExecution("w3auth-flow", executionData);

        List<AuthenticationExecutionInfoRepresentation> executions =
                adminClient.realm(REALM).flows().getExecutions("w3auth-flow");
        AuthenticationExecutionInfoRepresentation execution = executions.stream()
                .filter(e -> "w3auth-authenticator".equals(e.getProviderId()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("w3auth-authenticator execution not found"));
        execution.setRequirement("REQUIRED");
        adminClient.realm(REALM).flows().updateExecutions("w3auth-flow", execution);

        AuthenticatorConfigRepresentation configRep = new AuthenticatorConfigRepresentation();
        configRep.setAlias("w3auth-config");
        configRep.setConfig(Map.of(
                "expected-domain", "localhost",
                "expected-uri", "http://localhost:8080/callback"
        ));
        adminClient.realm(REALM).flows().newExecutionConfig(execution.getId(), configRep);

        realmRep = adminClient.realm(REALM).toRepresentation();
        realmRep.setBrowserFlow("w3auth-flow");
        adminClient.realm(REALM).update(realmRep);

        // DELIBERATELY OMITTED: disabling VERIFY_PROFILE / UPDATE_PROFILE /
        // update_profile_on_first_login. A stock realm never gets that either.
    }

    @Test
    void web3WalletLogin_completesOnStockRealmWithDefaultDeclarativeProfile() throws Exception {
        String authUrl = serverUrl + "/realms/" + REALM + "/protocol/openid-connect/auth" +
                "?client_id=test-app" +
                "&response_type=code" +
                "&scope=openid" +
                "&redirect_uri=" + URLEncoder.encode("http://localhost:8080/callback", StandardCharsets.UTF_8);

        HttpResponse<String> getResponse = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(authUrl)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(getResponse.statusCode()).isEqualTo(200);

        String htmlBody = getResponse.body();
        Matcher nonceMatcher = Pattern.compile("const nonce = \"([^\"]+)\"").matcher(htmlBody);
        assertThat(nonceMatcher.find()).isTrue();
        String nonce = nonceMatcher.group(1);

        Matcher actionMatcher = Pattern.compile("action=\"([^\"]+)\"").matcher(htmlBody);
        assertThat(actionMatcher.find()).isTrue();
        String actionUrl = actionMatcher.group(1).replace("&amp;", "&");
        if (actionUrl.startsWith("http://localhost:8080")) {
            actionUrl = serverUrl + actionUrl.substring("http://localhost:8080".length());
        }

        String issuedAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        String expiresAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now().plus(5, ChronoUnit.MINUTES));

        String message = "localhost wants you to sign in with your Ethereum account:\n" +
                EXPECTED_ADDRESS + "\n" +
                "\n" +
                "\n" +
                "URI: http://localhost:8080/callback\n" +
                "Version: 1\n" +
                "Chain ID: 1\n" +
                "Nonce: " + nonce + "\n" +
                "Issued At: " + issuedAt + "\n" +
                "Expiration Time: " + expiresAt;

        ECKeyPair keyPair = ECKeyPair.create(Numeric.hexStringToByteArray(PRIVATE_KEY));
        Sign.SignatureData sigData = Sign.signPrefixedMessage(message.getBytes(StandardCharsets.UTF_8), keyPair);
        byte[] sigBytes = new byte[65];
        System.arraycopy(sigData.getR(), 0, sigBytes, 0, 32);
        System.arraycopy(sigData.getS(), 0, sigBytes, 32, 32);
        sigBytes[64] = sigData.getV()[0];
        String signature = "0x" + Numeric.toHexStringNoPrefix(sigBytes);

        String messageHex = Numeric.toHexString(message.getBytes(StandardCharsets.UTF_8));
        String postBody = "accountId=" + URLEncoder.encode("eip155:1:" + EXPECTED_ADDRESS, StandardCharsets.UTF_8) +
                "&messageHex=" + URLEncoder.encode(messageHex, StandardCharsets.UTF_8) +
                "&signature=" + URLEncoder.encode(signature, StandardCharsets.UTF_8);

        HttpRequest postRequest = HttpRequest.newBuilder()
                .uri(URI.create(actionUrl))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(postBody))
                .build();

        HttpResponse<String> postResponse = httpClient.send(postRequest, HttpResponse.BodyHandlers.ofString());

        if (postResponse.statusCode() != 302) {
            System.err.println("POST request failed. Status: " + postResponse.statusCode());
            System.err.println("Response Body: " + postResponse.body());
        }
        assertThat(postResponse.statusCode())
                .as("a valid wallet signature must redirect, not challenge again or error")
                .isEqualTo(302);

        String redirectLocation = postResponse.headers().firstValue("Location").orElse("");

        // The regression this test guards: on a stock realm, a bare provisioned user
        // (no email/firstName/lastName) trips Keycloak's default declarative user profile,
        // and login diverts here instead of completing.
        assertThat(redirectLocation)
                .as("wallet login must not divert to a required-action page (e.g. VERIFY_PROFILE) "
                        + "on a realm with Keycloak's plain defaults")
                .doesNotContain("login-actions/required-action");

        assertThat(redirectLocation)
                .as("wallet login must complete directly: redirect to the client callback carrying an auth code")
                .startsWith("http://localhost:8080/callback")
                .contains("code=");
    }
}
