package com.w3auth.backend.verification;

import java.time.Instant;

import com.w3auth.backend.identity.Namespace;

/**
 * Parsed representation of an EIP-4361 (SIWE) message, produced by
 * {@link SiweMessageParser}. Immutable; stores fields exactly as they appear
 * in the wire message — no canonicalization or policy validation.
 */
public record SiweMessage(
        String domain,
        String address,
        String uri,
        String version,
        String chainId,
        String nonce,
        Instant issuedAt,
        Instant expiresAt) implements AuthMessage {

    public SiweMessage {
        requireNonBlank(domain, "domain");
        requireNonBlank(address, "address");
        requireNonBlank(uri, "uri");
        requireNonBlank(version, "version");
        requireNonBlank(chainId, "chainId");
        requireNonBlank(nonce, "nonce");
        if (issuedAt == null) throw new IllegalArgumentException("issuedAt must not be null");
        if (expiresAt == null) throw new IllegalArgumentException("expiresAt must not be null");
    }

    @Override
    public Namespace namespace() {
        return Namespace.EIP155;
    }

    private static void requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
    }
}
