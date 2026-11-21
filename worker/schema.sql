-- Table for the reports in D1. Apply once:
--   npx wrangler d1 execute csa-2026-01 --remote --file=schema.sql
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,        -- random, or the old KV key for reports moved over
  received TEXT NOT NULL,     -- time of receipt, ISO 8601 in UTC
  report TEXT NOT NULL        -- the report as JSON
);
CREATE INDEX IF NOT EXISTS reports_received ON reports (received, id);
