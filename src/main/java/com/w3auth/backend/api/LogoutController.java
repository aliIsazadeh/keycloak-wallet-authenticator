package com.w3auth.backend.api;

import com.w3auth.backend.usecase.Logout;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/auth")
class LogoutController {

    private final Logout logout;

    LogoutController(Logout logout) {
        this.logout = logout;
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void logout(@Valid @RequestBody LogoutRequest request) {
        logout.execute(request.refreshToken());
    }
}
