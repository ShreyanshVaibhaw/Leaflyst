-- Upgrade path for the columns added to 0001_events.sql.
--
-- The init directory only runs on a container's first start, so a fresh install
-- already has these columns from 0001 and this file is a harmless no-op. An
-- EXISTING deployment never re-runs init, so an operator must apply this file
-- by hand, as an admin user, before deploying the release that writes
-- schema_version 2:
--
--   clickhouse-client --user <admin> --queries-file 0002_event_schema_version.sql
--
-- Order matters. The columns must exist before the new code inserts them.
-- abx_app deliberately has no ALTER grant, which is what keeps the event log
-- append-only, so this cannot be self-applied by the application.
--
-- Defaults are chosen so pre-existing rows read back as exactly the version 1
-- events they were written as: schema_version 1, no operator.

ALTER TABLE abx.events ADD COLUMN IF NOT EXISTS schema_version UInt16 DEFAULT 1;
ALTER TABLE abx.events ADD COLUMN IF NOT EXISTS operator_ref String DEFAULT '';
