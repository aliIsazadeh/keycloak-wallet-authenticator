package com.w3auth.backend.api;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import com.w3auth.backend.verification.ChainClient;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;
import tools.jackson.databind.ObjectMapper;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end round-trip proof for M1: challenge → sign → verify → JWT.
 *
 * <p>Spins up real Postgres and Redis containers; exercises the full HTTP stack
 * with a real Ethereum key (Hardhat account #0). This is the "watched it work
 * end-to-end" test the task specification requires.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@Testcontainers
class VerifyFlowE2ETest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Container
    static final GenericContainer<?> REDIS =
            new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
                    .withExposedPorts(6379);

    @DynamicPropertySource
    static void redisProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
    }

    // Hardhat/Anvil account #0 — private key published in the Hardhat docs.
    private static final String HARDHAT_PRIVATE_KEY =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    private static final String HARDHAT_ADDRESS =
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

    // Matches application.yml local-dev default: Base64("abcdefghijklmnopqrstuvwxyz123456")
    private static final SecretKey SIGNING_KEY =
            Keys.hmacShaKeyFor(Base64.getDecoder().decode("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="));

    // The dispatcher calls chainClient.getCode before ecrecover. The E2E tests exercise
    // EOA verification only; mock ChainClient returns null (treated as "no code" → EOA path)
    // so no live RPC endpoint is needed.
    @MockitoBean
    ChainClient chainClient;

    @Autowired
    WebApplicationContext wac;

    @Autowired
    ObjectMapper objectMapper;

    MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(wac)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    /**
     * Full login round-trip:
     * 1. POST /v1/auth/challenge  — obtain a SIWE message
     * 2. Sign the message with the Hardhat key (EIP-191 personal_sign)
     * 3. POST /v1/auth/verify     — submit the signature, receive an access JWT
     * 4. Parse the JWT and assert sub == CAIP-10 string for the Hardhat address
     */
    @Test
    void fullLoginRoundTrip_returnsValidJwtWithCorrectSub() throws Exception {
        // Step 1: request a challenge for the Hardhat address on chain 1
        String accountId = "eip155:1:" + HARDHAT_ADDRESS;
        MvcResult challengeResult = mvc.perform(post("/v1/auth/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"accountId\":\"" + accountId + "\"}"))
                .andExpect(status().isCreated())
                .andReturn();

        Map<?, ?> challengeBody = objectMapper.readValue(
                challengeResult.getResponse().getContentAsString(), Map.class);
        String rawMessage = (String) challengeBody.get("message");
        assertThat(rawMessage).isNotBlank();

        // Step 2: sign the raw SIWE message (EIP-191 personal_sign — same as wallet.signMessage)
        ECKeyPair keyPair = ECKeyPair.create(Numeric.hexStringToByteArray(HARDHAT_PRIVATE_KEY));
        Sign.SignatureData sigData =
                Sign.signPrefixedMessage(rawMessage.getBytes(StandardCharsets.UTF_8), keyPair);
        String signature = "0x" + Numeric.toHexStringNoPrefix(concatSignature(sigData));

        // Step 3: verify — submit signed message, expect access JWT
        MvcResult verifyResult = mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"message\":" + objectMapper.writeValueAsString(rawMessage)
                                + ",\"signature\":\"" + signature + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isString())
                .andExpect(jsonPath("$.expiresAt").isString())
                .andReturn();

        Map<?, ?> verifyBody = objectMapper.readValue(
                verifyResult.getResponse().getContentAsString(), Map.class);
        String token = (String) verifyBody.get("token");

        // Step 4: parse and verify the JWT — sub must be the CAIP-10 identity key
        Claims claims = Jwts.parser()
                .verifyWith(SIGNING_KEY)
                .clock(() -> Date.from(java.time.Instant.now()))
                .build()
                .parseSignedClaims(token)
                .getPayload();

        // The identity key is namespace:address (no chainId — per architecture §2).
        // CaipAccountId.of lowercases the address.
        assertThat(claims.getSubject()).startsWith("eip155:");
        assertThat(claims.getSubject()).containsIgnoringCase(HARDHAT_ADDRESS.substring(2));
    }

    @Test
    void replay_secondVerifyWithSameNonce_returns401() throws Exception {
        String accountId = "eip155:1:" + HARDHAT_ADDRESS;
        MvcResult challengeResult = mvc.perform(post("/v1/auth/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"accountId\":\"" + accountId + "\"}"))
                .andReturn();

        Map<?, ?> challengeBody = objectMapper.readValue(
                challengeResult.getResponse().getContentAsString(), Map.class);
        String rawMessage = (String) challengeBody.get("message");

        ECKeyPair keyPair = ECKeyPair.create(Numeric.hexStringToByteArray(HARDHAT_PRIVATE_KEY));
        Sign.SignatureData sigData =
                Sign.signPrefixedMessage(rawMessage.getBytes(StandardCharsets.UTF_8), keyPair);
        String signature = "0x" + Numeric.toHexStringNoPrefix(concatSignature(sigData));

        String body = "{\"message\":" + objectMapper.writeValueAsString(rawMessage)
                + ",\"signature\":\"" + signature + "\"}";

        // First verify — must succeed (nonce consumed here)
        mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk());

        // Second verify with the same message — nonce already consumed, must be 401
        mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized());
    }

    private static byte[] concatSignature(Sign.SignatureData sig) {
        byte[] out = new byte[65];
        byte[] r = sig.getR();
        byte[] s = sig.getS();
        System.arraycopy(r, 0, out, 0, Math.min(r.length, 32));
        System.arraycopy(s, 0, out, 32, Math.min(s.length, 32));
        out[64] = sig.getV()[0];
        return out;
    }
}
