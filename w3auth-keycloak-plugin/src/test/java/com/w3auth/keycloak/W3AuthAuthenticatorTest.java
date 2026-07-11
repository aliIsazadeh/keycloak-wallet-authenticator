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
        formData.putSingle("messageHex", toHex(message));
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
        formData.putSingle("messageHex", toHex(message));
        formData.putSingle("signature", "0x" + "00".repeat(65));

        when(request.getDecodedFormParameters()).thenReturn(formData);

        authenticator.action(context);

        verify(formsProvider).setError(contains("Nonce mismatch"));
        verify(context).challenge(any(Response.class));
        verify(context, never()).setUser(any());
        verify(context, never()).success();
    }

    @Test
    void action_elevenLine_withStatement_successfulVerification() {
        // Real-world: exact format the w3auth-login.ftl template builds (11 lines, statement present)
        String nonce = "testNonce123456";
        sessionNotes.put("w3auth-nonce", nonce);

        String issuedAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        String expiresAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now().plus(5, ChronoUnit.MINUTES));

        String message = "localhost wants you to sign in with your Ethereum account:\n" +
                EXPECTED_ADDRESS + "\n" +
                "\n" +
                "Sign in to Keycloak.\n" +
                "\n" +
                "URI: http://localhost:8080\n" +
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

        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.putSingle("accountId", "eip155:1:" + EXPECTED_ADDRESS);
        formData.putSingle("messageHex", toHex(message));
        formData.putSingle("signature", signature);

        when(request.getDecodedFormParameters()).thenReturn(formData);
        when(userProvider.getUserByUsername(realm, "eip155:" + EXPECTED_ADDRESS)).thenReturn(null);
        when(userProvider.addUser(realm, "eip155:" + EXPECTED_ADDRESS)).thenReturn(user);

        authenticator.action(context);

        verify(context).setUser(user);
        verify(authSession).removeAuthNote("w3auth-nonce");
        verify(context).success();
    }

    @Test
    void action_missingCredentials_rendersFormWithNonceAndError() {
        // No form fields submitted — simulates a bare POST with nothing filled in
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        when(request.getDecodedFormParameters()).thenReturn(formData);

        authenticator.action(context);

        // A fresh nonce must have been generated and stored so the retry has a valid challenge
        verify(authSession).setAuthNote(eq("w3auth-nonce"), anyString());
        // The template attributes must be set so FreeMarker can render ${nonce} etc.
        verify(formsProvider).setAttribute(eq("nonce"), anyString());
        verify(formsProvider).setAttribute(eq("expectedDomain"), anyString());
        verify(formsProvider).setAttribute(eq("expectedUri"), anyString());
        // The error message must be present
        verify(formsProvider).setError(contains("Missing wallet login credentials"));
        verify(formsProvider).createForm("w3auth-login.ftl");
        verify(context).challenge(any(Response.class));
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
        formData.putSingle("messageHex", toHex(message));
        formData.putSingle("signature", "0x" + "00".repeat(65));

        when(request.getDecodedFormParameters()).thenReturn(formData);

        authenticator.action(context);

        verify(formsProvider).setError(contains("Domain mismatch"));
        verify(context).challenge(any(Response.class));
    }

    /**
     * Reproduces the real browser transport that every prior in-process test missed.
     *
     * <p>The wallet signs the exact "\n"-delimited UTF-8 bytes. When that plaintext was
     * submitted through an HTML form, the {@code application/x-www-form-urlencoded}
     * serializer rewrote every "\n" to "\r\n", so the server hashed different bytes than
     * the wallet signed and recovery failed. The fix transports the message as hex of the
     * signed bytes; the server hex-decodes back to those exact bytes. Here we CRLF-normalize
     * the plaintext (as a form would) and confirm we do NOT send that — we send hex of the
     * original "\n" bytes, and verification recovers the correct signer.
     */
    @Test
    void action_hexTransport_immuneToFormCrlfNormalization_success() {
        String nonce = "testNonce123456";
        sessionNotes.put("w3auth-nonce", nonce);

        String issuedAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        String expiresAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now().plus(5, ChronoUnit.MINUTES));

        String message = "localhost wants you to sign in with your Ethereum account:\n" +
                EXPECTED_ADDRESS + "\n" +
                "\n" +
                "Sign in to Keycloak.\n" +
                "\n" +
                "URI: http://localhost:8080\n" +
                "Version: 1\n" +
                "Chain ID: 1\n" +
                "Nonce: " + nonce + "\n" +
                "Issued At: " + issuedAt + "\n" +
                "Expiration Time: " + expiresAt;

        // Sanity: what a form WOULD have transmitted is byte-different from what was signed.
        String crlfNormalized = message.replace("\n", "\r\n");
        org.junit.jupiter.api.Assertions.assertNotEquals(message, crlfNormalized);

        String signature = signPrefixed(message);

        // Transport = hex of the EXACT signed "\n" bytes, not the plaintext.
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.putSingle("accountId", "eip155:1:" + EXPECTED_ADDRESS);
        formData.putSingle("messageHex", toHex(message));
        formData.putSingle("signature", signature);

        when(request.getDecodedFormParameters()).thenReturn(formData);
        when(userProvider.getUserByUsername(realm, "eip155:" + EXPECTED_ADDRESS)).thenReturn(null);
        when(userProvider.addUser(realm, "eip155:" + EXPECTED_ADDRESS)).thenReturn(user);

        authenticator.action(context);

        verify(context).setUser(user);
        verify(authSession).removeAuthNote("w3auth-nonce");
        verify(context).success();
    }

    /**
     * The exact demo failure: a signature made over "\n" bytes, but the message bytes that
     * reach the verifier are the CRLF-normalized form (as the old plaintext transport
     * delivered). The recovered signer no longer matches the address claim, so the flow must
     * fail closed. This proves the verifier is byte-sensitive and that only byte-exact
     * transport (the hex fix above) can pass.
     */
    @Test
    void action_crlfCorruptedBytes_failsSignerMatch() {
        String nonce = "testNonce123456";
        sessionNotes.put("w3auth-nonce", nonce);

        String issuedAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        String expiresAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now().plus(5, ChronoUnit.MINUTES));

        String message = "localhost wants you to sign in with your Ethereum account:\n" +
                EXPECTED_ADDRESS + "\n" +
                "\n" +
                "Sign in to Keycloak.\n" +
                "\n" +
                "URI: http://localhost:8080\n" +
                "Version: 1\n" +
                "Chain ID: 1\n" +
                "Nonce: " + nonce + "\n" +
                "Issued At: " + issuedAt + "\n" +
                "Expiration Time: " + expiresAt;

        // Sign the "\n" bytes, but transport the CRLF-normalized bytes the form would have sent.
        String signature = signPrefixed(message);
        String crlfNormalized = message.replace("\n", "\r\n");

        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.putSingle("accountId", "eip155:1:" + EXPECTED_ADDRESS);
        formData.putSingle("messageHex", toHex(crlfNormalized));
        formData.putSingle("signature", signature);

        when(request.getDecodedFormParameters()).thenReturn(formData);

        authenticator.action(context);

        verify(formsProvider).setError(contains("does not match message address"));
        verify(context).challenge(any(Response.class));
        verify(context, never()).setUser(any());
        verify(context, never()).success();
    }

    // -------------------------------------------------------------------------
    // Wallet-binding security tests (pre-registration attack guard)
    // -------------------------------------------------------------------------

    /**
     * Regression guard for normal repeat login. An existing user provisioned by this
     * authenticator carries both wallet attributes; the flow must accept it.
     */
    @Test
    void action_existingUserWithMatchingWalletAttributes_repeatLoginSucceeds() {
        String nonce = "testNonce123456";
        sessionNotes.put("w3auth-nonce", nonce);

        String issuedAt  = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        String expiresAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now().plus(5, ChronoUnit.MINUTES));

        String message = "localhost wants you to sign in with your Ethereum account:\n" +
                EXPECTED_ADDRESS + "\n\n\n" +
                "URI: http://localhost:8080\n" +
                "Version: 1\nChain ID: 1\n" +
                "Nonce: " + nonce + "\n" +
                "Issued At: " + issuedAt + "\n" +
                "Expiration Time: " + expiresAt;

        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.putSingle("accountId", "eip155:1:" + EXPECTED_ADDRESS);
        formData.putSingle("messageHex", toHex(message));
        formData.putSingle("signature", signPrefixed(message));

        when(request.getDecodedFormParameters()).thenReturn(formData);
        when(userProvider.getUserByUsername(realm, "eip155:" + EXPECTED_ADDRESS)).thenReturn(user);
        when(user.getFirstAttribute("w3auth_namespace")).thenReturn("EIP155");
        when(user.getFirstAttribute("w3auth_address")).thenReturn(EXPECTED_ADDRESS);

        authenticator.action(context);

        verify(userProvider, never()).addUser(any(), any());
        verify(context).setUser(user);
        verify(authSession).removeAuthNote("w3auth-nonce");
        verify(context).success();
    }

    /**
     * Pre-registration attack reproduction. A form-registered account that uses the
     * wallet identity key as its username will have NO w3auth_* attributes. Even though
     * the victim signs a valid SIWE message, the authenticator must fail closed and
     * never call setUser/success on the attacker's account.
     */
    @Test
    void action_existingUserWithNoWalletAttributes_preRegisteredAttacker_failsClosed() {
        String nonce = "testNonce123456";
        sessionNotes.put("w3auth-nonce", nonce);

        String issuedAt  = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        String expiresAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now().plus(5, ChronoUnit.MINUTES));

        String message = "localhost wants you to sign in with your Ethereum account:\n" +
                EXPECTED_ADDRESS + "\n\n\n" +
                "URI: http://localhost:8080\n" +
                "Version: 1\nChain ID: 1\n" +
                "Nonce: " + nonce + "\n" +
                "Issued At: " + issuedAt + "\n" +
                "Expiration Time: " + expiresAt;

        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.putSingle("accountId", "eip155:1:" + EXPECTED_ADDRESS);
        formData.putSingle("messageHex", toHex(message));
        formData.putSingle("signature", signPrefixed(message));

        when(request.getDecodedFormParameters()).thenReturn(formData);
        // Attacker's pre-registered account: exists by username, has no wallet attributes.
        when(userProvider.getUserByUsername(realm, "eip155:" + EXPECTED_ADDRESS)).thenReturn(user);
        when(user.getFirstAttribute("w3auth_namespace")).thenReturn(null);
        when(user.getFirstAttribute("w3auth_address")).thenReturn(null);

        authenticator.action(context);

        verify(context, never()).setUser(any());
        verify(context, never()).success();
        verify(context).challenge(any(Response.class));
        // Generic message: must not describe the collision to the client.
        verify(formsProvider).setError(eq("Authentication failed."));
    }

    /**
     * Existing user has a w3auth_address attribute, but it belongs to a different wallet
     * (e.g., an account that was incorrectly linked or tampered with). Must fail closed.
     */
    @Test
    void action_existingUserWithMismatchedAddress_failsClosed() {
        String nonce = "testNonce123456";
        sessionNotes.put("w3auth-nonce", nonce);

        String issuedAt  = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        String expiresAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now().plus(5, ChronoUnit.MINUTES));

        String message = "localhost wants you to sign in with your Ethereum account:\n" +
                EXPECTED_ADDRESS + "\n\n\n" +
                "URI: http://localhost:8080\n" +
                "Version: 1\nChain ID: 1\n" +
                "Nonce: " + nonce + "\n" +
                "Issued At: " + issuedAt + "\n" +
                "Expiration Time: " + expiresAt;

        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.putSingle("accountId", "eip155:1:" + EXPECTED_ADDRESS);
        formData.putSingle("messageHex", toHex(message));
        formData.putSingle("signature", signPrefixed(message));

        when(request.getDecodedFormParameters()).thenReturn(formData);
        when(userProvider.getUserByUsername(realm, "eip155:" + EXPECTED_ADDRESS)).thenReturn(user);
        when(user.getFirstAttribute("w3auth_namespace")).thenReturn("EIP155");
        // Attribute carries a different address — the binding check must reject this.
        when(user.getFirstAttribute("w3auth_address")).thenReturn("0x000000000000000000000000000000000000dead");

        authenticator.action(context);

        verify(context, never()).setUser(any());
        verify(context, never()).success();
        verify(context).challenge(any(Response.class));
        verify(formsProvider).setError(eq("Authentication failed."));
    }

    /**
     * EIP-55 checksum casing: one wallet stores the address lowercase, another as
     * checksummed mixed-case. equalsIgnoreCase must bridge the gap so the same wallet
     * owner is never locked out by a casing inconsistency between sessions.
     */
    @Test
    void action_existingUserWithDifferentCasingAttribute_matchesCaseInsensitivelyForEip155() {
        String nonce = "testNonce123456";
        sessionNotes.put("w3auth-nonce", nonce);

        String issuedAt  = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        String expiresAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now().plus(5, ChronoUnit.MINUTES));

        // Message (and therefore parsed.address()) uses the canonical lowercase form.
        String message = "localhost wants you to sign in with your Ethereum account:\n" +
                EXPECTED_ADDRESS + "\n\n\n" +
                "URI: http://localhost:8080\n" +
                "Version: 1\nChain ID: 1\n" +
                "Nonce: " + nonce + "\n" +
                "Issued At: " + issuedAt + "\n" +
                "Expiration Time: " + expiresAt;

        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.putSingle("accountId", "eip155:1:" + EXPECTED_ADDRESS);
        formData.putSingle("messageHex", toHex(message));
        formData.putSingle("signature", signPrefixed(message));

        when(request.getDecodedFormParameters()).thenReturn(formData);
        when(userProvider.getUserByUsername(realm, "eip155:" + EXPECTED_ADDRESS)).thenReturn(user);
        when(user.getFirstAttribute("w3auth_namespace")).thenReturn("EIP155");
        // Attribute was stored in a previous session using a checksummed/uppercase form.
        when(user.getFirstAttribute("w3auth_address")).thenReturn(EXPECTED_ADDRESS.toUpperCase());

        authenticator.action(context);

        verify(userProvider, never()).addUser(any(), any());
        verify(context).setUser(user);
        verify(context).success();
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

    /** Mirrors the FTL transport: hex of the message's exact UTF-8 bytes, 0x-prefixed. */
    private static String toHex(String message) {
        return Numeric.toHexString(message.getBytes(StandardCharsets.UTF_8));
    }
}
