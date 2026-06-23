package com.w3auth.backend.api;

import com.w3auth.backend.usecase.AuthResult;
import com.w3auth.backend.usecase.VerifyAndAuthenticate;
import com.w3auth.backend.verification.VerificationException;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/auth")
class VerifyController {

    private final VerifyAndAuthenticate verifyAndAuthenticate;

    VerifyController(VerifyAndAuthenticate verifyAndAuthenticate) {
        this.verifyAndAuthenticate = verifyAndAuthenticate;
    }

    @PostMapping("/verify")
    VerifyResponse verify(@Valid @RequestBody VerifyRequest request) throws VerificationException {
        AuthResult result = verifyAndAuthenticate.execute(request.message(), request.signature());
        return new VerifyResponse(result.token(), result.refreshToken(), result.expiresAt());
    }
}
