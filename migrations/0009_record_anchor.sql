-- roots migration 0008 — anchor records to the dreamtree chain.
--
-- Every active record's commitment (a sha256 over its immutable stored bytes) is
-- anchored on-chain via anchord (see dreamtree/docs/anchoring.md). We store the
-- assigned seed id, the tx hash, and the block height so the wallet can show
-- "anchored at height N, tx …" and anyone can verify the commitment on-chain.
--
-- Additive + backfillable: existing rows default to 'pending' and get swept.
ALTER TABLE records ADD COLUMN seed_id INTEGER;
ALTER TABLE records ADD COLUMN anchor_tx TEXT;
ALTER TABLE records ADD COLUMN anchor_height INTEGER;
ALTER TABLE records ADD COLUMN anchor_state TEXT NOT NULL DEFAULT 'pending'
  CHECK (anchor_state IN ('pending', 'anchored', 'failed', 'skipped'));

CREATE INDEX idx_records_anchor_state ON records(anchor_state);
