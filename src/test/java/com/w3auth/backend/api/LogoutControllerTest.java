package com.w3auth.backend.api;

import com.w3auth.backend.usecase.Logout;
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class LogoutControllerTest {

    @Mock
    Logout logout;

    @InjectMocks
    LogoutController controller;

    MockMvc mvc;

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
    void validRequest_returns204() throws Exception {
        doNothing().when(logout).execute(any());

        mvc.perform(post("/v1/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":"some-opaque-token"}
                                """))
                .andExpect(status().isNoContent())
                .andExpect(content().string(""));
    }

    // ── malformed input → 400 ─────────────────────────────────────────────────

    @Test
    void blankRefreshToken_returns400() throws Exception {
        mvc.perform(post("/v1/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":""}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void missingRefreshToken_returns400() throws Exception {
        mvc.perform(post("/v1/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }
}
