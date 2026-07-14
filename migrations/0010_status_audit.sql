-- roots migration 0010 — revocation audit for the Bitstring status engine.
--
-- status_counters + credential_status (migration 0002) already hold the per-issuer
-- slot allocation and the two status bits, so the index bookkeeping is in place.
-- What was missing is ACCOUNTABILITY: an operator flipping a revocation/suspension
-- bit should be an attributable action, not an anonymous mutation. These two
-- columns record who changed a credential's status and why (populated by the
-- operator-gated revoke/suspend/reinstate routes). Additive + backfillable.
ALTER TABLE credential_status ADD COLUMN reason TEXT;
ALTER TABLE credential_status ADD COLUMN updated_by TEXT;
