-- roots migration 0010 — bound anchor retries (audit F9/starvation).
--
-- The sweep retried pending+failed forever, oldest first: 25 permanently
-- failing old rows would occupy every batch and starve newer records. Track
-- attempts; the sweep orders by attempts (fresh rows first) and stops
-- retrying after a cap. Capped-out rows stay 'failed' and are visible to
-- the admin backfill, which resets attempts to force a retry.
ALTER TABLE records ADD COLUMN anchor_attempts INTEGER NOT NULL DEFAULT 0;
