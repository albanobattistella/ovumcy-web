CREATE TABLE IF NOT EXISTS register_pickup_tokens (
    nonce VARCHAR(64) PRIMARY KEY,
    user_id BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_register_pickup_tokens_expires_at
    ON register_pickup_tokens (expires_at);
