package com.w3auth.backend.api;

import com.w3auth.backend.usecase.AuthResult;
import com.w3auth.backend.usecase.VerifyAndAuthenticate;
import com.w3auth.backend.verification.VerificationException;
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
class VerifyControllerTest {

    @Mock
    VerifyAndAuthenticate verifyAndAuthenticate;

    @InjectMocks
    VerifyController controller;

    MockMvc mvc;

    private static final Instant EXPIRES_AT = Instant.parse("2026-06-20T12:10:00Z");
    private static final AuthResult STUB_RESULT =
            new AuthResult("eyJhbGciOiJIUzI1NiJ9.stub.sig", "stub-refresh-token", EXPIRES_AT);

    @BeforeEach
    void setUp() {
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.afterPropertiesSet();

        mvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler())
                .setValidator(validator)
                .build();
    }

    // ── happy path ────────────────────────────────────────────────────────────

    @Test
    void validRequest_returns200WithTokenAndExpiry() throws Exception {
        when(verifyAndAuthenticate.execute(any(), any())).thenReturn(STUB_RESULT);

        mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"message":"example.com wants you to sign in...","signature":"0xabc"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value(STUB_RESULT.token()))
                .andExpect(jsonPath("$.refreshToken").value(STUB_RESULT.refreshToken()))
                .andExpect(jsonPath("$.expiresAt").value("2026-06-20T12:10:00Z"));
    }

    // ── authentication failure → 401 ──────────────────────────────────────────

    @Test
    void verificationException_returns401() throws Exception {
        when(verifyAndAuthenticate.execute(any(), any()))
                .thenThrow(new VerificationException("nonce missing, expired, or already used"));

        mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"message":"example.com wants you to sign in...","signature":"0xabc"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").isString());
    }

    // ── malformed input → 400 ────────────────────────────────────────────────

    @Test
    void missingMessage_returns400() throws Exception {
        mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"signature":"0xabc"}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void missingSignature_returns400() throws Exception {
        mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"message":"example.com wants you to sign in..."}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void blankMessage_returns400() throws Exception {
        mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"message":"","signature":"0xabc"}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void emptyBody_returns400() throws Exception {
        mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }
}
