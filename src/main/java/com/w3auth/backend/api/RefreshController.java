package com.w3auth.backend.api;

import com.w3auth.backend.usecase.RefreshResult;
import com.w3auth.backend.usecase.RefreshSession;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/auth")
class RefreshController {

    private final RefreshSession refreshSession;

    RefreshController(RefreshSession refreshSession) {
        this.refreshSession = refreshSession;
    }

    @PostMapping("/refresh")
    RefreshResponse refresh(@Valid @RequestBody RefreshRequest request) {
        RefreshResult result = refreshSession.execute(request.refreshToken());
        return new RefreshResponse(result.token(), result.refreshToken(), result.expiresAt());
    }
}
