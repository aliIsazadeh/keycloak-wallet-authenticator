package com.w3auth.backend.api;

import java.time.Instant;

record RefreshResponse(String token, String refreshToken, Instant expiresAt) {}
