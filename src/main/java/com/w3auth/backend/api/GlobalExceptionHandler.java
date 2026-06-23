package com.w3auth.backend.api;

import com.w3auth.backend.session.RefreshTokenException;
import com.w3auth.backend.verification.VerificationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    Map<String, String> handleIllegalArgument(IllegalArgumentException ex) {
        return Map.of("error", ex.getMessage());
    }

    // Spring's default MethodArgumentNotValidException body leaks internal binding details.
    // Collect field errors into a single readable message in the same {"error":...} shape.
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    Map<String, String> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> fe.getField() + " " + fe.getDefaultMessage())
                .collect(Collectors.joining(", "));
        return Map.of("error", message);
    }

    // VerificationException means the request was well-formed but authentication failed.
    // 401 is correct: the client presented credentials that did not pass verification.
    // 400 would be wrong — the JSON was valid, the inputs were present; auth itself rejected them.
    @ExceptionHandler(VerificationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    Map<String, String> handleVerification(VerificationException ex) {
        return Map.of("error", ex.getMessage());
    }

    // All RefreshTokenException causes produce a byte-identical 401 — no oracle distinguishes
    // reuse from expiry or a missing token at the wire. Log level alone branches on reason:
    // reuse is a theft signal (WARN); all other failures are routine (DEBUG).
    @ExceptionHandler(RefreshTokenException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    Map<String, String> handleRefreshToken(RefreshTokenException ex) {
        if (ex.reason() == RefreshTokenException.Reason.REUSE_DETECTED) {
            log.warn("refresh token reuse detected — possible theft; family revoked");
        } else {
            log.debug("refresh token rejected: {}", ex.reason());
        }
        return Map.of("error", "invalid refresh token");
    }
}
