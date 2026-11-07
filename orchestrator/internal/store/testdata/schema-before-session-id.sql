-- SPDX-License-Identifier: Apache-2.0
-- The controller database's last schema before the session id column took its neutral name: every
-- column an earlier controller added, in the order it added them (the passthrough's request_body
-- among them), every table and index, and the session id still as hermes_session_id. Frozen: never
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
	evidence_refs TEXT,
	task_description TEXT,
	request_body TEXT,
	response_body TEXT
, local_backend_used TEXT, input_tokens INTEGER, output_tokens INTEGER, reasoning_tokens INTEGER, api_calls INTEGER, retry_of_run_id TEXT, completed INTEGER, failed INTEGER, turn_exit_reason TEXT, cost_usd REAL, cache_read_tokens INTEGER, aux_by_task TEXT, injected_lessons TEXT, injected_runbooks TEXT, prompt_sha256 TEXT, prompt_bytes INTEGER, attempts INTEGER, submitted_by TEXT, failure_class TEXT, resubmits INTEGER, parent_profile_revision TEXT, last_call_prompt_tokens INTEGER, max_call_prompt_tokens INTEGER, max_tokens_requested INTEGER, wait_cause TEXT, model TEXT, finished_pending INTEGER);
CREATE INDEX idx_jobs_state ON jobs(state);
CREATE INDEX idx_jobs_seq ON jobs(seq);
CREATE UNIQUE INDEX idx_jobs_idempotency
	ON jobs(idempotency_key) WHERE idempotency_key IS NOT NULL AND idempotency_key != '';
CREATE TABLE event_outbox (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	event_id TEXT NOT NULL UNIQUE,
	body TEXT NOT NULL,
	created_at TEXT NOT NULL,
	attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE backend_drains (
	backend TEXT PRIMARY KEY,
	since TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_jobs_retry_of
	ON jobs(retry_of_run_id) WHERE retry_of_run_id IS NOT NULL AND retry_of_run_id != '';
