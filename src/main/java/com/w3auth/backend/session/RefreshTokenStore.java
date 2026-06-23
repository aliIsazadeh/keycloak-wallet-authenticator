package com.w3auth.backend.session;

import java.util.UUID;

/**
 * Port for refresh-token persistence. Core — no Spring or JPA imports.
 *
 * <p>Implementations must guarantee atomicity on rotation: exactly one concurrent
 * caller wins for a given live token; the loser throws without revoking the family.
 */
public interface RefreshTokenStore {

    /**
     * Mints a fresh token in the given family and persists the row.
     *
     * @param identityId the wallet identity this session belongs to
     * @param familyId   the rotation family; supply {@code UUID.randomUUID()} for a new login
     * @return the raw (client-visible) token and the stored row snapshot
     */
    TokenGrant issue(UUID identityId, UUID familyId);

    /**
     * Rotates a live refresh token: mints a replacement in the same family,
     * links the old row to the new one, and returns both the new raw token and
     * the new row.
     *
     * <p>Failure cases (all throw {@link RefreshTokenException}):
     * <ul>
     *   <li>Token hash not found or token expired</li>
     *   <li>Family already revoked</li>
     *   <li>Token already rotated (reuse/theft signal) — also revokes the family</li>
     *   <li>Lost benign concurrent race (another caller rotated the same token first)</li>
     * </ul>
     *
     * @param rawToken the opaque token string previously given to the client
     */
    TokenGrant rotate(String rawToken);

    /**
     * Revokes all live tokens in the given family by setting {@code revoked_at}.
     * Idempotent: already-revoked rows are unaffected.
     */
    void revokeFamily(UUID familyId);

    /**
     * Hashes {@code rawToken}, looks up its row, and revokes the whole family.
     * Idempotent and silent: if the token is unknown or the family is already revoked,
     * this is a no-op. Used by Logout — never signals token validity to the caller.
     */
    void revokeFamilyByToken(String rawToken);
}
