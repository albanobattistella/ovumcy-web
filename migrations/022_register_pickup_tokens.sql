-- Server-side single-use tracking for the POST /api/auth/register pickup
-- cookie. The sealed ovumcy_register_pickup cookie carries an opaque nonce
-- whose row is inserted here. GET /register/welcome atomically consumes the
-- row via
--   UPDATE register_pickup_tokens
--   SET consumed_at = ?
--   WHERE nonce = ? AND consumed_at IS NULL AND expires_at > ?
-- so a captured cookie cannot be replayed to mint a second auth session
-- inside the 5-minute TTL. Decoy pickups for duplicate-email registrations
-- are not inserted. Their nonces never resolve on consume, which is
-- observationally identical to a real pickup that has already been used
-- or has expired.

CREATE TABLE IF NOT EXISTS register_pickup_tokens (
    nonce TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_register_pickup_tokens_expires_at
    ON register_pickup_tokens (expires_at);
