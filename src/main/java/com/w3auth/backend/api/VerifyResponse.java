package com.w3auth.backend.api;

import java.time.Instant;

record VerifyResponse(String token, String refreshToken, Instant expiresAt) {}
