package com.w3auth.backend.session;

/**
 * Holds the output of a token mint operation (issue or rotate).
 *
 * <p>{@code rawToken} is the opaque secret given to the client — it is never stored.
 * {@code token} is the stored row snapshot; callers read identityId and familyId from it
 * without a follow-up query.
 */
public record TokenGrant(String rawToken, RefreshToken token) {}
