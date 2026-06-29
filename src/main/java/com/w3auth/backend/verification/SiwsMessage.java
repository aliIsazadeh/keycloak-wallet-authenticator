package com.w3auth.backend.verification;

import java.time.Instant;

/**
 * Parsed representation of a SIWS (Sign-In With Solana) message, produced by
 * {@link SiwsMessageParser}. Immutable; stores fields exactly as they appear
 * in the wire message — no canonicalization or policy validation.
 */
public record SiwsMessage(
        String domain,
        String address,
        String uri,
        String version,
        String chainId,
        String nonce,
        Instant issuedAt,
        Instant expiresAt) {

    public SiwsMessage {
        requireNonBlank(domain, "domain");
        requireNonBlank(address, "address");
        requireNonBlank(uri, "uri");
        requireNonBlank(version, "version");
        requireNonBlank(chainId, "chainId");
        requireNonBlank(nonce, "nonce");
        if (issuedAt == null) throw new IllegalArgumentException("issuedAt must not be null");
        if (expiresAt == null) throw new IllegalArgumentException("expiresAt must not be null");
    }

    private static void requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
    }
}
