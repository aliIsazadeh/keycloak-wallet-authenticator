CREATE TABLE wallet_identity (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace     TEXT NOT NULL,
    address       TEXT NOT NULL,
    status        TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_wallet_identity_namespace_address UNIQUE (namespace, address)
);
