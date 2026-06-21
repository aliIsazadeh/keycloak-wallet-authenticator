package com.w3auth.backend.infrastructure;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh_token")
class RefreshTokenEntity {

    @Id
    @Column(columnDefinition = "uuid")
    private UUID id;

    @Column(name = "family_id", nullable = false, columnDefinition = "uuid")
    private UUID familyId;

    @Column(name = "identity_id", nullable = false, columnDefinition = "uuid")
    private UUID identityId;

    @Column(name = "token_hash", nullable = false)
    private String tokenHash;

    @Column(name = "replaced_by", columnDefinition = "uuid")
    private UUID replacedBy;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected RefreshTokenEntity() {}

    RefreshTokenEntity(UUID id, UUID familyId, UUID identityId,
                       String tokenHash, Instant expiresAt, Instant createdAt) {
        this.id = id;
        this.familyId = familyId;
        this.identityId = identityId;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
        this.createdAt = createdAt;
    }

    UUID getId()           { return id; }
    UUID getFamilyId()     { return familyId; }
    UUID getIdentityId()   { return identityId; }
    String getTokenHash()  { return tokenHash; }
    UUID getReplacedBy()   { return replacedBy; }
    Instant getExpiresAt() { return expiresAt; }
    Instant getRevokedAt() { return revokedAt; }
    Instant getCreatedAt() { return createdAt; }
}
