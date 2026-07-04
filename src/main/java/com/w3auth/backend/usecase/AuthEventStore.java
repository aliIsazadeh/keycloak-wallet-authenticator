package com.w3auth.backend.usecase;

import java.time.Instant;
import java.util.UUID;

/**
 * Core port for audit logging auth events.
 */
public interface AuthEventStore {

    /**
     * Records an authentication event (e.g. login, logout, refresh).
     *
     * @param identityId the primary key of the wallet identity (can be null for failed logins)
     * @param eventType  the action type (e.g. LOGIN_SUCCESS, LOGIN_FAILED, REFRESH_SUCCESS, REFRESH_FAILED, LOGOUT)
     * @param ipAddress  the client's IP address (can be null)
     * @param userAgent  the client's User-Agent string (can be null)
     * @param details    additional debug information (can be null)
     * @param timestamp  the time the event occurred
     */
    void logEvent(UUID identityId, String eventType, String ipAddress, String userAgent, String details, Instant timestamp);
}
