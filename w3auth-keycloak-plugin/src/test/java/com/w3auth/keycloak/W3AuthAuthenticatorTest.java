package com.w3auth.keycloak;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class W3AuthAuthenticatorTest {

    // Hardhat Account #0
    private static final String PRIVATE_KEY =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    private static final String EXPECTED_ADDRESS =
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

    private W3AuthAuthenticator authenticator;
    
    private AuthenticationFlowContext context;
    private AuthenticationSessionModel authSession;
    private KeycloakSession session;
    private RealmModel realm;
    private UserProvider userProvider;
    private UserModel user;
    private HttpRequest request;
    private LoginFormsProvider formsProvider;
    private AuthenticatorConfigModel configModel;

    private Map<String, String> configMap;
    private Map<String, String> sessionNotes;

    @BeforeEach
    void setUp() {
        authenticator = new W3AuthAuthenticator();

        context = mock(AuthenticationFlowContext.class);
        authSession = mock(AuthenticationSessionModel.class);
        session = mock(KeycloakSession.class);
        realm = mock(RealmModel.class);
        userProvider = mock(UserProvider.class);
        user = mock(UserModel.class);
        request = mock(HttpRequest.class);
        formsProvider = mock(LoginFormsProvider.class);
        configModel = mock(AuthenticatorConfigModel.class);

        configMap = new HashMap<>();
        configMap.put("expected-domain", "localhost");
        configMap.put("expected-uri", "http://localhost:8080");

        sessionNotes = new HashMap<>();

        // Setup common mocks
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(realm);
        when(context.getHttpRequest()).thenReturn(request);
        when(context.form()).thenReturn(formsProvider);
        when(context.getAuthenticatorConfig()).thenReturn(configModel);
        when(configModel.getConfig()).thenReturn(configMap);
        when(session.users()).thenReturn(userProvider);

        // Mock auth note storage
        doAnswer(inv -> {
            sessionNotes.put(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(authSession).setAuthNote(anyString(), anyString());

        doAnswer(inv -> sessionNotes.get(inv.getArgument(0)))
                .when(authSession).getAuthNote(anyString());

        // Mock forms provider mapping
        when(formsProvider.setAttribute(anyString(), any())).thenReturn(formsProvider);
        when(formsProvider.setError(anyString())).thenReturn(formsProvider);
        when(formsProvider.createForm(anyString())).thenReturn(mock(Response.class));
    }

    @Test
    void authenticate_setsNonceAndChallengesForm() {
        authenticator.authenticate(context);

        verify(authSession).setAuthNote(eq("w3auth-nonce"), anyString());
        verify(formsProvider).setAttribute(eq("nonce"), anyString());
        verify(formsProvider).setAttribute("expectedDomain", "localhost");
        verify(formsProvider).setAttribute("expectedUri", "http://localhost:8080");
        verify(formsProvider).createForm("w3auth-login.ftl");
        verify(context).challenge(any(Response.class));
    }

    @Test
    void action_successfulVerification_provisionsAndLogsInUser() {
        String nonce = "testNonce123456";
        sessionNotes.put("w3auth-nonce", nonce);

        String issuedAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        String expiresAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now().plus(5, ChronoUnit.MINUTES));

        String message = "localhost wants you to sign in with your Ethereum account:\n" +
                EXPECTED_ADDRESS + "\n" +
                "\n" +
                "\n" +
                "URI: http://localhost:8080\n" +
                "Version: 1\n" +
                "Chain ID: 1\n" +
                "Nonce: " + nonce + "\n" +
                "Issued At: " + issuedAt + "\n" +
                "Expiration Time: " + expiresAt;

        // Sign the SIWE message using web3j
        ECKeyPair keyPair = ECKeyPair.create(Numeric.hexStringToByteArray(PRIVATE_KEY));
        Sign.SignatureData sigData = Sign.signPrefixedMessage(message.getBytes(StandardCharsets.UTF_8), keyPair);
        byte[] sigBytes = new byte[65];
        System.arraycopy(sigData.getR(), 0, sigBytes, 0, 32);
        System.arraycopy(sigData.getS(), 0, sigBytes, 32, 32);
        sigBytes[64] = sigData.getV()[0];
        String signature = "0x" + Numeric.toHexStringNoPrefix(sigBytes);

        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.putSingle("accountId", "eip155:1:" + EXPECTED_ADDRESS);
        formData.putSingle("message", message);
        formData.putSingle("signature", signature);

        when(request.getDecodedFormParameters()).thenReturn(formData);
        when(userProvider.getUserByUsername(realm, "eip155:" + EXPECTED_ADDRESS)).thenReturn(null);
        when(userProvider.addUser(realm, "eip155:" + EXPECTED_ADDRESS)).thenReturn(user);

        authenticator.action(context);

        verify(userProvider).addUser(realm, "eip155:" + EXPECTED_ADDRESS);
        verify(user).setAttribute("w3auth_address", List.of(EXPECTED_ADDRESS));
        verify(user).setAttribute("w3auth_namespace", List.of("EIP155"));
        verify(context).setUser(user);
        verify(authSession).removeAuthNote("w3auth-nonce");
        verify(context).success();
    }

    @Test
    void action_nonceMismatch_failsFlow() {
        sessionNotes.put("w3auth-nonce", "validNonce");

        String message = "localhost wants you to sign in with your Ethereum account:\n" +
                EXPECTED_ADDRESS + "\n" +
                "\n" +
                "\n" +
                "URI: http://localhost:8080\n" +
                "Version: 1\n" +
                "Chain ID: 1\n" +
                "Nonce: invalidNonce\n" + // Submitted message has wrong nonce
                "Issued At: 2026-07-07T12:00:00Z\n" +
                "Expiration Time: 2026-07-07T12:05:00Z";

        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.putSingle("accountId", "eip155:1:" + EXPECTED_ADDRESS);
        formData.putSingle("message", message);
        formData.putSingle("signature", "0x" + "00".repeat(65));

        when(request.getDecodedFormParameters()).thenReturn(formData);

        authenticator.action(context);

        verify(formsProvider).setError(contains("Nonce mismatch"));
        verify(context).challenge(any(Response.class));
        verify(context, never()).setUser(any());
        verify(context, never()).success();
    }

    @Test
    void action_domainMismatch_failsFlow() {
        String nonce = "testNonce123456";
        sessionNotes.put("w3auth-nonce", nonce);

        String message = "malicious.com wants you to sign in with your Ethereum account:\n" + // Domain mismatch
                EXPECTED_ADDRESS + "\n" +
                "\n" +
                "\n" +
                "URI: http://localhost:8080\n" +
                "Version: 1\n" +
                "Chain ID: 1\n" +
                "Nonce: " + nonce + "\n" +
                "Issued At: 2026-07-07T12:00:00Z\n" +
                "Expiration Time: 2026-07-07T12:05:00Z";

        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.putSingle("accountId", "eip155:1:" + EXPECTED_ADDRESS);
        formData.putSingle("message", message);
        formData.putSingle("signature", "0x" + "00".repeat(65));

        when(request.getDecodedFormParameters()).thenReturn(formData);

        authenticator.action(context);

        verify(formsProvider).setError(contains("Domain mismatch"));
        verify(context).challenge(any(Response.class));
    }
}
