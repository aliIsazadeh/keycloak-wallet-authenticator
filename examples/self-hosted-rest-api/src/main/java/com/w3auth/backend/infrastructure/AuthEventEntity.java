package com.w3auth.backend.infrastructure;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "auth_event")
class AuthEventEntity {

    @Id
    @Column(columnDefinition = "uuid")
    private UUID id;

    @Column(name = "identity_id", columnDefinition = "uuid")
    private UUID identityId;

    @Column(name = "event_type", nullable = false)
    private String eventType;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "user_agent")
    private String userAgent;

    @Column
    private String details;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected AuthEventEntity() {
    }

    AuthEventEntity(UUID id, UUID identityId, String eventType, String ipAddress, String userAgent, String details, Instant createdAt) {
        this.id = id;
        this.identityId = identityId;
        this.eventType = eventType;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.details = details;
        this.createdAt = createdAt;
    }

    UUID getId() {
        return id;
    }

    UUID getIdentityId() {
        return identityId;
    }

    String getEventType() {
        return eventType;
    }

    String getIpAddress() {
        return ipAddress;
    }

    String getUserAgent() {
        return userAgent;
    }

    String getDetails() {
        return details;
    }

    Instant getCreatedAt() {
        return createdAt;
    }
}
