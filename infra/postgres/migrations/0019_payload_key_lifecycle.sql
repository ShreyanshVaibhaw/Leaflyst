-- Phase 21: make the payload master key rotatable.
--
-- Before this, nothing recorded WHICH master key wrapped a given data key.
-- Rotating meant every existing payload became permanently unreadable, with no
-- way to detect that before doing it. For a product whose erasure guarantee is
-- "destroy the key", that is load-bearing infrastructure, not an operational
-- detail.
--
-- 'k1' is the id the single configured key is given when no explicit id is
-- set, so existing rows are correct as written and no backfill is needed.

ALTER TABLE payload_segments
    ADD COLUMN master_key_id TEXT NOT NULL DEFAULT 'k1';

-- Answers "is any segment still wrapped by a retired key?" - the question the
-- re-wrap job and the startup check both ask.
CREATE INDEX payload_segments_master_key_idx
    ON payload_segments (master_key_id);
