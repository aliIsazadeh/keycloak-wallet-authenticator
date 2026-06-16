package com.w3auth.backend.api;

import com.w3auth.backend.challenge.Challenge;
import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.identity.Namespace;
import com.w3auth.backend.usecase.RequestChallenge;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class ChallengeControllerTest {

    @Mock
    RequestChallenge requestChallenge;

    @InjectMocks
    ChallengeController controller;

    MockMvc mvc;

    private static final Instant ISSUED_AT  = Instant.parse("2026-06-16T10:00:00Z");
    private static final Instant EXPIRES_AT = Instant.parse("2026-06-16T10:05:00Z");

    private static final CaipAccountId ACCOUNT =
            CaipAccountId.of(Namespace.EIP155, "1", "0xabc1234567890abc1234567890abc12345678901");

    private static final Challenge STUB_CHALLENGE = new Challenge(
            ACCOUNT, "testnonce", "example.com", "https://example.com", ISSUED_AT, EXPIRES_AT);

    @BeforeEach
    void setUp() {
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.afterPropertiesSet();

        mvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler())
                .setValidator(validator)
                .build();
    }

    @Test
    void validRequest_returns201WithNonceAndMessage() throws Exception {
        when(requestChallenge.execute(any())).thenReturn(STUB_CHALLENGE);

        mvc.perform(post("/v1/auth/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"accountId":"eip155:1:0xabc1234567890abc1234567890abc12345678901"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.nonce").value("testnonce"))
                .andExpect(jsonPath("$.message").isString())
                .andExpect(jsonPath("$.expiresAt").value("2026-06-16T10:05:00Z"));
    }

    @Test
    void blankAccountId_returns400() throws Exception {
        mvc.perform(post("/v1/auth/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"accountId":""}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void missingAccountId_returns400() throws Exception {
        mvc.perform(post("/v1/auth/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void malformedAccountId_returns400WithError() throws Exception {
        mvc.perform(post("/v1/auth/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"accountId":"not-a-caip-id"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").isString());
    }
}
