-- refresh_token is the V1 session record (see ARCHITECTURE.md §4).
-- One row per issued/rotated token; the chain of rotations is a linked list via replaced_by.
--
-- FK choices:
--   identity_id → wallet_identity(id): every session belongs to an identity; no cascade
--     delete because identity deletion is not a V1 flow.
--   replaced_by → refresh_token(id): self-referencing FK; nullable (NULL on the first
--     token in a family). Within rotate(), the INSERT of the new row happens before the
--     UPDATE that sets old.replaced_by = new.id, so the FK target already exists at
--     statement time — no DEFERRABLE needed.
--
-- Index choices:
--   idx_refresh_token_family_id: revokeFamily() issues UPDATE WHERE family_id = ?; without
--     this index that scan hits every row in the table.
--   token_hash UNIQUE constraint: creates an implicit B-tree index automatically;
--     rotate() does a point-lookup by hash on every call, so this is the hot path.
--     A duplicate explicit index is not created — the constraint index serves both purposes.

CREATE TABLE refresh_token (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    family_id     UUID        NOT NULL,
    identity_id   UUID        NOT NULL REFERENCES wallet_identity(id),
    token_hash    TEXT        NOT NULL UNIQUE,
    replaced_by   UUID        REFERENCES refresh_token(id),
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ NULL,
    created_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_refresh_token_family_id ON refresh_token (family_id);
