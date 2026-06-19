package com.w3auth.backend.verification;

import java.util.Objects;

/**
 * The inputs to {@link SignatureVerifier#verify}: the parsed SIWE message,
 * the original raw plaintext (the exact bytes the wallet signed — needed for
 * EIP-191 prefix hashing), and the raw signature string from the client.
 *
 * <p>{@code rawMessage} is kept separate from {@code message} because
 * {@code SiweMessage} is a parsed record; reconstructing the original wire
 * bytes from its fields would require duplicating the factory's serialization
 * logic. Passing the raw string through from {@code VerifyAndAuthenticate}
 * (where it is already in scope) is the minimal, correct approach.
 */
public record VerificationRequest(SiweMessage message, String rawMessage, String signature) {

    public VerificationRequest {
        Objects.requireNonNull(message, "message must not be null");
        if (rawMessage == null || rawMessage.isBlank()) {
            throw new IllegalArgumentException("rawMessage must not be blank");
        }
        if (signature == null || signature.isBlank()) {
            throw new IllegalArgumentException("signature must not be blank");
        }
    }
}
