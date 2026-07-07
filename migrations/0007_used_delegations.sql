-- roots migration 0007 — single-use holder delegations (replay defense).
--
-- Each holder delegation carries a unique `jti` and is single-use: verifying it
-- consumes the jti here, so a captured token cannot be replayed within its (short)
-- validity window. D1 is strongly consistent, so this catches replays across
-- Worker isolates (an in-memory cache would not). Rows are bounded by the token
-- TTL and swept opportunistically on each verify.
CREATE TABLE used_delegations (
  jti        TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL   -- unix seconds; row is dead once now() passes this
);
CREATE INDEX idx_used_delegations_exp ON used_delegations(expires_at);
