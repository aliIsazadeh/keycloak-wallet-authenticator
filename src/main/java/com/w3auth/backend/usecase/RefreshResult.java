package com.w3auth.backend.usecase;

import java.time.Instant;

/**
 * The result of a successful {@link RefreshSession#execute} call.
 *
 * @param token        the new signed access JWT
 * @param refreshToken the new raw refresh token to give the client (replaces the one just consumed)
 * @param expiresAt    when the access token expires — included so the controller can populate the
 *                     response without re-parsing the JWT
 */
public record RefreshResult(String token, String refreshToken, Instant expiresAt) {}
