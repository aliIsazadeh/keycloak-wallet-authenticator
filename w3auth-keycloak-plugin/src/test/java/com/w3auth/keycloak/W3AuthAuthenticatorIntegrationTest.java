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

import jakarta.ws.rs.core.Response;
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

@Testcontainers
class W3AuthAuthenticatorIntegrationTest {

    private static final String PRIVATE_KEY =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    private static final String EXPECTED_ADDRESS =
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

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
        httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .cookieHandler(new java.net.CookieManager())
                .build();

        // 1. Connect to Keycloak using Admin Client
        Keycloak adminClient = KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm("master")
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build();

        // 2. Create test realm 'w3auth-test'
        RealmRepresentation realmRep = new RealmRepresentation();
        realmRep.setRealm("w3auth-test");
        realmRep.setEnabled(true);

        // Provision client 'test-app'
        ClientRepresentation clientRep = new ClientRepresentation();
        clientRep.setClientId("test-app");
        clientRep.setEnabled(true);
        clientRep.setRedirectUris(List.of("http://localhost:8080/callback"));
        clientRep.setPublicClient(true);
        clientRep.setDirectAccessGrantsEnabled(true);
        realmRep.setClients(List.of(clientRep));

        adminClient.realms().create(realmRep);

        // 3. Create custom authentication flow 'w3auth-flow'
        AuthenticationFlowRepresentation flow = new AuthenticationFlowRepresentation();
        flow.setAlias("w3auth-flow");
        flow.setProviderId("basic-flow");
        flow.setDescription("Web3 Wallet Signature Login Flow");
        flow.setTopLevel(true);
        flow.setBuiltIn(false);

        adminClient.realm("w3auth-test").flows().createFlow(flow);

        Map<String, Object> executionData = new HashMap<>();
        executionData.put("provider", "w3auth-authenticator");
        adminClient.realm("w3auth-test").flows().addExecution("w3auth-flow", executionData);

        // Retrieve and configure the execution to REQUIRED
        List<AuthenticationExecutionInfoRepresentation> executions = adminClient.realm("w3auth-test").flows().getExecutions("w3auth-flow");
        AuthenticationExecutionInfoRepresentation execution = executions.stream()
                .filter(e -> "w3auth-authenticator".equals(e.getProviderId()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("w3auth-authenticator execution not found"));

        execution.setRequirement("REQUIRED");
        adminClient.realm("w3auth-test").flows().updateExecutions("w3auth-flow", execution);

        // 5. Add configurations to execution
        AuthenticatorConfigRepresentation configRep = new AuthenticatorConfigRepresentation();
        configRep.setAlias("w3auth-config");
        configRep.setConfig(Map.of(
                "expected-domain", "localhost",
                "expected-uri", "http://localhost:8080/callback"
        ));
        adminClient.realm("w3auth-test").flows().newExecutionConfig(execution.getId(), configRep);

        // 6. Bind flow as browser login binding for 'w3auth-test'
        realmRep = adminClient.realm("w3auth-test").toRepresentation();
        realmRep.setBrowserFlow("w3auth-flow");
        adminClient.realm("w3auth-test").update(realmRep);

        // 7. Disable profile verification required actions to avoid login interception
        adminClient.realm("w3auth-test").flows().getRequiredActions().forEach(action -> {
            if ("VERIFY_PROFILE".equals(action.getAlias()) || 
                "UPDATE_PROFILE".equals(action.getAlias()) || 
                "update_profile_on_first_login".equals(action.getAlias())) {
                action.setEnabled(false);
                adminClient.realm("w3auth-test").flows().updateRequiredAction(action.getAlias(), action);
            }
        });
    }

    @Test
    void web3WalletLogin_successfulAuthAndUserFederation() throws Exception {
        // Step 1: Initiate OAuth flow to hit the authenticator (GET challenge form)
        String authUrl = serverUrl + "/realms/w3auth-test/protocol/openid-connect/auth" +
                "?client_id=test-app" +
                "&response_type=code" +
                "&scope=openid" +
                "&redirect_uri=" + URLEncoder.encode("http://localhost:8080/callback", StandardCharsets.UTF_8);

        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(URI.create(authUrl))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);

        String htmlBody = response.body();
        assertThat(htmlBody).contains("Web3 Authentication");

        // Step 2: Extract nonce and form action URL from HTML
        Pattern noncePattern = Pattern.compile("const nonce = \"([^\"]+)\"");
        Matcher nonceMatcher = noncePattern.matcher(htmlBody);
        assertThat(nonceMatcher.find()).isTrue();
        String nonce = nonceMatcher.group(1);

        Pattern actionPattern = Pattern.compile("action=\"([^\"]+)\"");
        Matcher actionMatcher = actionPattern.matcher(htmlBody);
        assertThat(actionMatcher.find()).isTrue();
        String rawActionUrl = actionMatcher.group(1);
        String actionUrl = rawActionUrl.replace("&amp;", "&");
        if (actionUrl.startsWith("http://localhost:8080")) {
            actionUrl = serverUrl + actionUrl.substring("http://localhost:8080".length());
        }

        // Step 3: Sign SIWE message programmatically
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

        // Step 4: POST credentials to action URL. The browser transports the message as hex of
        // the exact signed bytes (the FTL does this to survive the form serializer's
        // "\n" -> "\r\n" normalization); mirror that here by sending messageHex, not plaintext.
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
            System.err.println("Response Headers: " + postResponse.headers().map());
            System.err.println("Response Body: " + postResponse.body());
        }

        // Step 5: Assert redirection success (302 Found) back to redirect callback
        assertThat(postResponse.statusCode()).isEqualTo(302);
        String redirectLocation = postResponse.headers().firstValue("Location").orElse("");
        assertThat(redirectLocation).startsWith("http://localhost:8080/callback");
        assertThat(redirectLocation).contains("code=");

        // Step 6: Verify that the user has been created in Keycloak
        Keycloak adminClient = KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm("master")
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build();

        String expectedUsername = "eip155:" + EXPECTED_ADDRESS;
        List<UserRepresentation> users = adminClient.realm("w3auth-test").users().searchByUsername(expectedUsername, true);
        assertThat(users).hasSize(1);
        UserRepresentation userRep = users.get(0);
        assertThat(userRep.getUsername()).isEqualTo(expectedUsername);

        // Assert attributes
        Map<String, List<String>> attributes = userRep.getAttributes();
        assertThat(attributes.get("w3auth_address")).containsExactly(EXPECTED_ADDRESS);
        assertThat(attributes.get("w3auth_namespace")).containsExactly("EIP155");

        // Wallet users must be first-class citizens. Keycloak's addUser() auto-grants the realm
        // default role, which in a standard realm composites account:view-profile/manage-account —
        // the roles the Account Console REST API requires (without them it returns 401). Assert the
        // provisioned user actually carries the default role, so wallet logins get account access.
        List<RoleRepresentation> realmRoles = adminClient.realm("w3auth-test").users()
                .get(userRep.getId()).roles().realmLevel().listAll();
        assertThat(realmRoles).extracting(RoleRepresentation::getName)
                .contains("default-roles-w3auth-test");
    }

    /**
     * Step-1 measurement: submits a SIWE message whose domain field carries an XSS payload and
     * asserts that the rendered error page does not contain the raw {@code <script>} tag.
     *
     * <p>The domain check fires before signature verification, so a dummy signature is enough.
     * The real nonce is required so the nonce check passes and the flow reaches the domain check.
     *
     * <p>Two defences gate this path after the fix:
     * <ol>
     *   <li>The {@code catch} block now uses a fixed generic string, so attacker-controlled
     *       exception content never reaches {@code setError} at all.</li>
     *   <li>Keycloak 25's FreeMarker templates use the HTML output format: {@code ${message.summary}}
     *       is auto-escaped — {@code <} → {@code &lt;} — as confirmed by this test.</li>
     * </ol>
     */
    @Test
    void errorMessages_xssPayloadInDomain_renderedPageIsSafe() throws Exception {
        // Initiate a fresh OIDC flow to obtain a new nonce and action URL.
        String authUrl = serverUrl + "/realms/w3auth-test/protocol/openid-connect/auth"
                + "?client_id=test-app&response_type=code&scope=openid&redirect_uri="
                + URLEncoder.encode("http://localhost:8080/callback", StandardCharsets.UTF_8);

        HttpResponse<String> getResp = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(authUrl)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(getResp.statusCode()).isEqualTo(200);

        String html = getResp.body();
        Matcher nonceMatcher = Pattern.compile("const nonce = \"([^\"]+)\"").matcher(html);
        assertThat(nonceMatcher.find()).as("nonce not found in challenge form").isTrue();
        String nonce = nonceMatcher.group(1);

        Matcher actionMatcher = Pattern.compile("action=\"([^\"]+)\"").matcher(html);
        assertThat(actionMatcher.find()).as("action URL not found in challenge form").isTrue();
        String actionUrl = actionMatcher.group(1).replace("&amp;", "&");
        if (actionUrl.startsWith("http://localhost:8080")) {
            actionUrl = serverUrl + actionUrl.substring("http://localhost:8080".length());
        }

        // Build a syntactically valid SIWE message whose domain is an XSS payload.
        // detectNamespace passes (line ends with "...Ethereum account:"); the parser
        // succeeds; the nonce check passes (real nonce); the domain check throws with
        // the attacker domain in the exception message.
        String xssPayload = "<script>alert(1)</script>";
        String issuedAt  = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        String expiresAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now().plus(5, ChronoUnit.MINUTES));

        String hostileMessage = xssPayload + " wants you to sign in with your Ethereum account:\n"
                + EXPECTED_ADDRESS + "\n\n\n"
                + "URI: http://localhost:8080/callback\n"
                + "Version: 1\nChain ID: 1\n"
                + "Nonce: " + nonce + "\n"
                + "Issued At: " + issuedAt + "\n"
                + "Expiration Time: " + expiresAt;

        String messageHex = Numeric.toHexString(hostileMessage.getBytes(StandardCharsets.UTF_8));

        String postBody = "accountId=" + URLEncoder.encode("eip155:1:" + EXPECTED_ADDRESS, StandardCharsets.UTF_8)
                + "&messageHex=" + URLEncoder.encode(messageHex, StandardCharsets.UTF_8)
                // Signature is irrelevant — the domain check fires before it.
                + "&signature=" + URLEncoder.encode("0x" + "00".repeat(65), StandardCharsets.UTF_8);

        HttpResponse<String> postResp = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(actionUrl))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(postBody))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        // The authenticator re-challenges with the error form (200, not a redirect).
        assertThat(postResp.statusCode()).isEqualTo(200);
        String errorHtml = postResp.body();
        assertThat(errorHtml).as("login form should be re-rendered").contains("Web3 Authentication");

        // Primary assertion: raw XSS payload must not appear in the rendered page.
        assertThat(errorHtml)
                .as("raw <script> tag must not appear in rendered HTML")
                .doesNotContain(xssPayload);

        // Secondary assertion: the generic error message IS shown (fix evidence).
        assertThat(errorHtml)
                .as("generic error message should be present")
                .contains("Wallet verification failed. Please try again.");
    }
}
