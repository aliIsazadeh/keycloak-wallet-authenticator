package com.w3auth.backend.api;

import com.w3auth.backend.session.RefreshTokenException;
import com.w3auth.backend.usecase.RefreshResult;
import com.w3auth.backend.usecase.RefreshSession;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class RefreshControllerTest {

    @Mock
    RefreshSession refreshSession;

    @InjectMocks
    RefreshController controller;

    MockMvc mvc;

    private static final Instant EXPIRES_AT = Instant.parse("2026-06-23T10:10:00Z");
    private static final RefreshResult STUB_RESULT = new RefreshResult(
            "eyJhbGciOiJIUzI1NiJ9.stub.sig",
            "new-raw-refresh-token",
            EXPIRES_AT);

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
    void validRequest_returns200WithTokens() throws Exception {
        when(refreshSession.execute(any())).thenReturn(STUB_RESULT);

        mvc.perform(post("/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":"some-opaque-token"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value(STUB_RESULT.token()))
                .andExpect(jsonPath("$.refreshToken").value(STUB_RESULT.refreshToken()))
                .andExpect(jsonPath("$.expiresAt").value("2026-06-23T10:10:00Z"));
    }

    // ── malformed input → 400 ─────────────────────────────────────────────────

    @Test
    void blankRefreshToken_returns400() throws Exception {
        mvc.perform(post("/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":""}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void missingRefreshToken_returns400() throws Exception {
        mvc.perform(post("/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    // ── byte-identical 401 — the load-bearing security test ──────────────────

    @Test
    void reuseAndExpired_produceByteIdenticalResponses() throws Exception {
        when(refreshSession.execute(any()))
                .thenThrow(new RefreshTokenException(
                        RefreshTokenException.Reason.REUSE_DETECTED,
                        "refresh token reuse detected — family revoked"))
                .thenThrow(new RefreshTokenException(
                        RefreshTokenException.Reason.EXPIRED,
                        "refresh token expired — a completely different internal message"));

        String bodyOnReuse = mvc.perform(post("/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":"spent-token"}
                                """))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        String bodyOnExpiry = mvc.perform(post("/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":"expired-token"}
                                """))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        assertThat(bodyOnReuse)
                .as("reuse and expiry must produce byte-identical wire responses — no oracle")
                .isEqualTo(bodyOnExpiry);
    }
}
