package com.w3auth.backend.api;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/v1/auth")
class MeController {

    @GetMapping("/me")
    Map<String, String> me(Authentication authentication) {
        return Map.of("sub", (String) authentication.getPrincipal());
    }
}
