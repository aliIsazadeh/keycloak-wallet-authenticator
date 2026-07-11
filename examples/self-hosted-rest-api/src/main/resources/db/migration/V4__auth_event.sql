CREATE TABLE auth_event (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id   UUID REFERENCES wallet_identity(id),
    event_type    TEXT NOT NULL,
    ip_address    TEXT,
    user_agent    TEXT,
    details       TEXT,
    created_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_auth_event_identity_id ON auth_event (identity_id);
