-- roots migration 0004 — generalize the record_events audit chain.
--
-- roots holds self/tool records, not just credentials, so the OPENING event of a
-- self-authored record is 'created' — not 'issued'/'imported', which carry
-- credential semantics. Widen the CHECK to include it. record_events is empty
-- (roots is undeployed) so a drop + recreate is safe; append-only forward.
DROP INDEX IF EXISTS idx_record_events_record;
DROP TABLE record_events;
CREATE TABLE record_events (
  id          TEXT PRIMARY KEY,
  record_id   TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
  event       TEXT NOT NULL CHECK (event IN ('created','issued','imported','retracted','reinstated')),
  reason      TEXT,
  actor       TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_record_events_record ON record_events(record_id, created_at);
