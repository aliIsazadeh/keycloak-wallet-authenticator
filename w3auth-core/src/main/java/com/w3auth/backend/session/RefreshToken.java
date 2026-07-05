package com.w3auth.backend.session;

import java.time.Instant;
import java.util.UUID;

/**
 * Immutable snapshot of a refresh_token row's meaningful state.
 * Core — no Spring or JPA imports.
 */
public record RefreshToken(
        UUID id,
        UUID familyId,
        UUID identityId,
        String tokenHash,
        UUID replacedBy,
        Instant expiresAt,
        Instant revokedAt,
        Instant createdAt
) {}
