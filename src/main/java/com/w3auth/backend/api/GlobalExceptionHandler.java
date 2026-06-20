package com.w3auth.backend.api;

import com.w3auth.backend.verification.VerificationException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
class GlobalExceptionHandler {

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
}
