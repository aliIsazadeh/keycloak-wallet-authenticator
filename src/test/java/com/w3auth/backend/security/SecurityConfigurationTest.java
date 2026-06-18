package com.w3auth.backend.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = {
        SecurityConfiguration.class,
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
    void publicAuthPath_get_isPermitted() throws Exception {
        mvc.perform(get("/v1/auth/ping"))
                .andExpect(status().isOk());
    }

    @Test
    void publicAuthPath_post_isPermittedAndStateless() throws Exception {
        mvc.perform(post("/v1/auth/ping"))
                .andExpect(status().isOk())                       // CSRF disabled: POST not blocked
                .andExpect(header().doesNotExist("Set-Cookie"));  // STATELESS: no JSESSIONID
    }

    @Test
    void unknownPath_isUnauthorized() throws Exception {
        mvc.perform(get("/locked"))
                .andExpect(status().isUnauthorized());            // anyRequest().authenticated() + 401 entry point
    }

    @RestController
    static class TestEndpoints {

        @GetMapping("/v1/auth/ping")
        String authPingGet() {
            return "ok";
        }

        @PostMapping("/v1/auth/ping")
        String authPingPost() {
            return "ok";
        }

        @GetMapping("/locked")
        String locked() {
            return "should-never-reach";
        }
    }
}