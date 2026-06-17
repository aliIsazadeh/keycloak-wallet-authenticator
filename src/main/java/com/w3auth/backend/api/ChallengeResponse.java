package com.w3auth.backend.api;

import java.time.Instant;

record ChallengeResponse(String nonce, String message, Instant expiresAt) {
}
