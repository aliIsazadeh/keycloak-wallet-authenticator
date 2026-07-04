package com.w3auth.backend.api;

import com.w3auth.backend.challenge.Challenge;
import com.w3auth.backend.challenge.SiweMessageFactory;
import com.w3auth.backend.challenge.SiwsMessageFactory;
import com.w3auth.backend.challenge.RateLimiter;
import com.w3auth.backend.identity.CaipAccountId;
import com.w3auth.backend.usecase.RequestChallenge;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/auth")
class ChallengeController {

    private final RequestChallenge requestChallenge;
    private final RateLimiter rateLimiter;

    ChallengeController(RequestChallenge requestChallenge, RateLimiter rateLimiter) {
        this.requestChallenge = requestChallenge;
        this.rateLimiter = rateLimiter;
    }

    @PostMapping("/challenge")
    @ResponseStatus(HttpStatus.CREATED)
    ChallengeResponse requestChallenge(@Valid @RequestBody ChallengeRequest request, HttpServletRequest servletRequest) {
        CaipAccountId account = CaipAccountId.parse(request.accountId());
        rateLimiter.checkLimit(servletRequest.getRemoteAddr(), account.address());
        Challenge challenge = requestChallenge.execute(account);
        String message = switch (challenge.account().namespace()) {
            case EIP155 -> SiweMessageFactory.create(challenge);
            case SOLANA -> SiwsMessageFactory.create(challenge);
        };
        return new ChallengeResponse(challenge.nonce(), message, challenge.expiresAt());
    }
}
