package com.w3auth.backend.security;

import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import com.w3auth.backend.session.JwtPolicy;
import com.w3auth.backend.session.JwtService;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.security.core.Authentication;

import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = {
        SecurityConfiguration.class,
        JwtAuthenticationFilterTest.TestConfig.class,
        JwtAuthenticationFilterTest.MeEndpoint.class
})
@ImportAutoConfiguration(ServletWebSecurityAutoConfiguration.class)
class JwtAuthenticationFilterTest {

    private static final String SECRET_B64 = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";
    private static final SecretKey SIGNING_KEY =
            Keys.hmacShaKeyFor(Base64.getDecoder().decode(SECRET_B64));

    private static final CaipAccountId ACCOUNT =
            CaipAccountId.of(Namespace.EIP155, "1", "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");

    @Autowired
    WebApplicationContext wac;

    @Autowired
    JwtService jwtService;

    MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders
                .webAppContextSetup(wac)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    @Test
    void noAuthHeader_isUnauthorized() throws Exception {
        mvc.perform(get("/v1/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void validToken_returns200WithCorrectSub() throws Exception {
        String token = jwtService.issue(ACCOUNT, Instant.now());

        mvc.perform(get("/v1/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string(ACCOUNT.toString()));
    }

    @Test
    void expiredToken_isUnauthorized() throws Exception {
        // Token issued far in the past; TTL is 10 min so it expired ~6 years ago
        String token = jwtService.issue(ACCOUNT, Instant.parse("2020-01-01T00:00:00Z"));

        mvc.perform(get("/v1/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tokenSignedWithWrongKey_isUnauthorized() throws Exception {
        SecretKey wrongKey = Keys.hmacShaKeyFor(
                Base64.getDecoder().decode("enl4YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="));
        JwtService impostor = new JwtService(
                new JwtPolicy(wrongKey, Duration.ofMinutes(10), "wallet-auth"));
        String token = impostor.issue(ACCOUNT, Instant.now());

        mvc.perform(get("/v1/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void malformedToken_isUnauthorizedNotServerError() throws Exception {
        mvc.perform(get("/v1/auth/me").header("Authorization", "Bearer not.a.jwt"))
                .andExpect(status().isUnauthorized());
    }

    // ── test infrastructure ───────────────────────────────────────────────────

    @TestConfiguration
    static class TestConfig {

        @Bean
        JwtPolicy jwtPolicy() {
            return new JwtPolicy(SIGNING_KEY, Duration.ofMinutes(10), "wallet-auth");
        }

        @Bean
        JwtService jwtService(JwtPolicy policy) {
            return new JwtService(policy);
        }

        @Bean
        Clock clock() {
            return Clock.systemUTC();
        }

        @Bean
        JwtAuthenticationFilter jwtAuthenticationFilter(JwtService jwtService, Clock clock) {
            return new JwtAuthenticationFilter(jwtService, clock);
        }
    }

    @RestController
    @RequestMapping("/v1/auth")
    static class MeEndpoint {

        @GetMapping("/me")
        String me(Authentication auth) {
            return (String) auth.getPrincipal();
        }
    }
}
