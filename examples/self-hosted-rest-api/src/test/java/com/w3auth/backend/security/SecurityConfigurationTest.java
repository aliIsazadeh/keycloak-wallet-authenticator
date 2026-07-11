package com.w3auth.backend.security;

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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;

import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = {
        SecurityConfiguration.class,
        SecurityConfigurationTest.TestConfig.class,
        SecurityConfigurationTest.TestEndpoints.class
})
@ImportAutoConfiguration(ServletWebSecurityAutoConfiguration.class)
class SecurityConfigurationTest {

    @Autowired
    WebApplicationContext wac;

    MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders
                .webAppContextSetup(wac)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    @Test
    void challengeEndpoint_isPublic() throws Exception {
        mvc.perform(post("/v1/auth/challenge"))
                .andExpect(status().isOk());
    }

    @Test
    void verifyEndpoint_isPublicAndStateless() throws Exception {
        mvc.perform(post("/v1/auth/verify"))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test
    void unknownPath_isUnauthorized() throws Exception {
        mvc.perform(get("/locked"))
                .andExpect(status().isUnauthorized());
    }

    @TestConfiguration
    static class TestConfig {

        private static final SecretKey KEY = Keys.hmacShaKeyFor(
                Base64.getDecoder().decode("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="));

        @Bean
        JwtPolicy jwtPolicy() {
            return new JwtPolicy(KEY, Duration.ofMinutes(10), "wallet-auth");
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
    static class TestEndpoints {

        @PostMapping("/v1/auth/challenge")
        String challenge() {
            return "ok";
        }

        @PostMapping("/v1/auth/verify")
        String verify() {
            return "ok";
        }

        @GetMapping("/locked")
        String locked() {
            return "should-never-reach";
        }
    }
}
