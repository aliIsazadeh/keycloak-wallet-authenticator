package com.w3auth.backend.infrastructure;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "wallet_identity")
class WalletIdentityEntity {

    @Id
    @Column(columnDefinition = "uuid")
    private UUID id;

    @Column(nullable = false)
    private String namespace;

    @Column(nullable = false)
    private String address;

    @Column(nullable = false)
    private String status;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "last_login_at", nullable = false)
    private Instant lastLoginAt;

    // JPA requires a no-arg constructor; entity is only ever read, never built by Java code
    protected WalletIdentityEntity() {}

    UUID getId()           { return id; }
    String getNamespace()  { return namespace; }
    String getAddress()    { return address; }
    String getStatus()     { return status; }
    Instant getCreatedAt() { return createdAt; }
    Instant getLastLoginAt() { return lastLoginAt; }
}
