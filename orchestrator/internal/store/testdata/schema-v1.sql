-- SPDX-License-Identifier: Apache-2.0
-- The controller database's first schema: the jobs table before any column was added, the session
-- id still under its old name, and neither the event outbox nor the drains table. Frozen: never
-- edit it (a later schema is a new fixture). migrate_test.go builds a database from it.
CREATE TABLE jobs (
	run_id TEXT PRIMARY KEY,
	agent_key TEXT NOT NULL,
	profile_id TEXT,
	profile_revision TEXT,
	priority INTEGER NOT NULL,
	seq INTEGER NOT NULL,
	state TEXT NOT NULL,
	shadow INTEGER NOT NULL DEFAULT 0,
	local_attempts INTEGER NOT NULL DEFAULT 0,
	cloud_fallback_used INTEGER NOT NULL DEFAULT 0,
	local_failed_reason TEXT,
	hermes_session_id TEXT,
	idempotency_key TEXT,
	created_at TEXT NOT NULL,
	started_at TEXT,
	deadline TEXT,
	finished_at TEXT,
	result_path TEXT,
	evidence_refs TEXT
);
CREATE INDEX idx_jobs_state ON jobs(state);
CREATE UNIQUE INDEX idx_jobs_idempotency
	ON jobs(idempotency_key) WHERE idempotency_key IS NOT NULL AND idempotency_key != '';
