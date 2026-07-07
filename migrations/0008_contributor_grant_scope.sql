-- roots migration 0008 — provenance + provenance-scoped read grants.
--
-- A contributor reads what it attested. `records.contributor` records the consumer
-- that wrote the record (its write-grant grantee). Read grants gain a `scope`:
--   'own' → the grantee may read only records it contributed (contributor = grantee)
--   'all' → cross-contributor read (the holder's explicit, purpose-gated grant)
-- The silent-wallet bootstrap auto-issues an 'own' read grant to the creating
-- consumer, so it can read back its own data without a separate consent step,
-- while another contributor's data stays private until the holder grants 'all'.
ALTER TABLE records ADD COLUMN contributor TEXT;  -- consumer that wrote it (provenance)
ALTER TABLE grants ADD COLUMN scope TEXT NOT NULL DEFAULT 'all' CHECK (scope IN ('own','all'));
CREATE INDEX idx_records_contributor ON records(wallet_id, contributor);
