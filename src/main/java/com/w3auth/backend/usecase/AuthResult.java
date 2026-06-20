package com.w3auth.backend.usecase;

import java.time.Instant;

/**
 * The result of a successful {@link VerifyAndAuthenticate#execute} call.
 *
 * @param token     the signed access JWT
 * @param expiresAt when the token expires — included so the controller can
 *                  populate the response without re-parsing the JWT
 */
public record AuthResult(String token, Instant expiresAt) {}
