// SPDX-License-Identifier: Apache-2.0

package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
)

// baseColumns are the jobs table's first columns, which every database this store reads has
// had from the start (with the session id under its old name, legacySessionColumn, in a
// database from before the rename).
var baseColumns = []column{
	{"run_id", "TEXT PRIMARY KEY"},
	{"agent_key", "TEXT NOT NULL"},
	{"profile_id", "TEXT"},
	{"profile_revision", "TEXT"},
	{"priority", "INTEGER NOT NULL"},
	{"seq", "INTEGER NOT NULL"},
	{"state", "TEXT NOT NULL"},
	{"shadow", "INTEGER NOT NULL DEFAULT 0"},
	{"local_attempts", "INTEGER NOT NULL DEFAULT 0"},
	{"cloud_fallback_used", "INTEGER NOT NULL DEFAULT 0"},
	{"local_failed_reason", "TEXT"},
	{"session_id", "TEXT"},
	{"idempotency_key", "TEXT"},
	{"created_at", "TEXT NOT NULL"},
	{"started_at", "TEXT"},
	{"deadline", "TEXT"},
	{"finished_at", "TEXT"},
	{"result_path", "TEXT"},
	{"evidence_refs", "TEXT"},
}

// addedColumns were added to the jobs table after it was first created, in this order. A
// database that lacks one gets it with ALTER TABLE ... ADD COLUMN; its existing rows read NULL
// there, which every reader takes as unknown. A new column goes at the end of this list, nullable
// and with no default, so that adding it is always this one statement.
var addedColumns = []column{
	{"task_description", "TEXT"},
	{"response_body", "TEXT"},
	{"local_backend_used", "TEXT"},
	{"input_tokens", "INTEGER"},
	{"output_tokens", "INTEGER"},
	{"reasoning_tokens", "INTEGER"},
	{"api_calls", "INTEGER"},
	{"retry_of_run_id", "TEXT"},
	{"completed", "INTEGER"},
	{"failed", "INTEGER"},
	{"turn_exit_reason", "TEXT"},
	{"cost_usd", "REAL"},
	{"cache_read_tokens", "INTEGER"},
	{"aux_by_task", "TEXT"},
	{"injected_lessons", "TEXT"},
	{"injected_runbooks", "TEXT"},
	{"prompt_sha256", "TEXT"},
	{"prompt_bytes", "INTEGER"},
	{"attempts", "INTEGER"},
	{"submitted_by", "TEXT"},
	{"failure_class", "TEXT"},
	{"resubmits", "INTEGER"},
	{"parent_profile_revision", "TEXT"},
	{"last_call_prompt_tokens", "INTEGER"},
	{"max_call_prompt_tokens", "INTEGER"},
	{"max_tokens_requested", "INTEGER"},
	{"wait_cause", "TEXT"},
	{"model", "TEXT"},
	{"finished_pending", "INTEGER"},
	{"task_sha256", "TEXT"},
}

// legacySessionColumn is the session id column's name before it took a runner-neutral one. A
// database that has it is migrated by renaming it to session_id, every value kept.
const legacySessionColumn = "hermes_session_id"

// retiredColumns are columns a database from an earlier controller may carry that this store
// neither reads nor writes (the request body of the HTTP passthrough, which is not ported). A
// migration leaves them, and their values, where they are.
func retiredColumns() []string { return []string{"request_body"} }

type column struct{ name, decl string }

// The other tables and the indexes, each created if missing. retryOfIndex is unique, with a
// plain fallback for a database that already holds two retries of one run (ensureRetryOfIndex).
const (
	outboxTableDDL = `CREATE TABLE IF NOT EXISTS event_outbox (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	event_id TEXT NOT NULL UNIQUE,
	body TEXT NOT NULL,
	created_at TEXT NOT NULL,
	attempts INTEGER NOT NULL DEFAULT 0
)`
	drainsTableDDL = `CREATE TABLE IF NOT EXISTS backend_drains (
	backend TEXT PRIMARY KEY,
	since TEXT NOT NULL
)`
	retryOfIndex            = "idx_jobs_retry_of"
	retryOfFallbackIndex    = "idx_jobs_retry_of_nonunique"
	retryOfIndexDDL         = `CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_retry_of ON jobs(retry_of_run_id) WHERE retry_of_run_id IS NOT NULL AND retry_of_run_id != ''`
	retryOfFallbackIndexDDL = `CREATE INDEX IF NOT EXISTS idx_jobs_retry_of_nonunique ON jobs(retry_of_run_id)`
)

// idx_jobs_idempotency_owner scopes an idempotency key to its submitter: two callers may use the
// same key, and one caller's key can neither find nor block another's run. It replaces the
// earlier global idx_jobs_idempotency, which a migration drops (the old index was stricter, so
// creating the new one over existing rows never fails).
var plainIndexes = []struct{ name, ddl string }{
	{"idx_jobs_state", `CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state)`},
	{"idx_jobs_seq", `CREATE INDEX IF NOT EXISTS idx_jobs_seq ON jobs(seq)`},
	{"idx_jobs_idempotency_owner", `CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_idempotency_owner ON jobs(COALESCE(submitted_by, ''), idempotency_key) WHERE idempotency_key IS NOT NULL AND idempotency_key != ''`},
	// The per-submitter bounds' counts (SubmitLimits), keyed as their queries are. The window's
	// count compares instants (julianday(created_at)), so its index is on that expression: an index
	// on the text column would bound the scan by the submitter only, every job it ever sent.
	{"idx_jobs_submitter_created_jd", `CREATE INDEX IF NOT EXISTS idx_jobs_submitter_created_jd ON jobs(COALESCE(submitted_by, ''), julianday(created_at))`},
	{"idx_jobs_submitter_state", `CREATE INDEX IF NOT EXISTS idx_jobs_submitter_state ON jobs(COALESCE(submitted_by, ''), state)`},
}

// globalIdempotencyIndex is the earlier, global key index.
const globalIdempotencyIndex = "idx_jobs_idempotency"

// textWindowIndex is the earlier window index, on created_at's text, which the window's count
// (julianday) cannot use past the submitter; a migration drops it.
const textWindowIndex = "idx_jobs_submitter_created"

// jobsTableDDL is the jobs table as a new database creates it: the base columns, then the added
// ones, so a new database and a migrated one have the same columns (a migrated one may carry
// retiredColumns too).
func jobsTableDDL() string {
	var b strings.Builder
	b.WriteString("CREATE TABLE jobs (\n")
	cols := append(append([]column(nil), baseColumns...), addedColumns...)
	for i, c := range cols {
		fmt.Fprintf(&b, "\t%s %s", c.name, c.decl)
		if i < len(cols)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString(")")
	return b.String()
}

// ErrAmbiguousSessionColumn: the jobs table has both the old and the new session id column. No
// version of the controller writes that, so neither column is trusted to hold the data and the
// database is refused rather than guessed at.
var ErrAmbiguousSessionColumn = errors.New("store: the jobs table has both " + legacySessionColumn + " and session_id; refusing to guess which holds the session ids")

// ErrNotAStoreDatabase: the file holds tables, but not a jobs table this store can read.
var ErrNotAStoreDatabase = errors.New("store: not a controller database")

// queryer is *sql.DB, *sql.Conn or *sql.Tx.
type queryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// schemaState is what inspectSchema found.
type schemaState struct {
	empty   bool // no table at all: a new database
	columns map[string]bool
	tables  map[string]bool
	indexes map[string]bool
}

func inspectSchema(q queryer) (schemaState, error) {
	st := schemaState{columns: map[string]bool{}, tables: map[string]bool{}, indexes: map[string]bool{}}
	rows, err := q.Query(`SELECT type, name FROM sqlite_master WHERE type IN ('table', 'index')`)
	if err != nil {
		return st, fmt.Errorf("inspect schema: %w", err)
	}
	for rows.Next() {
		var typ, name string
		if err := rows.Scan(&typ, &name); err != nil {
			rows.Close()
			return st, fmt.Errorf("inspect schema: %w", err)
		}
		if typ == "table" {
			st.tables[name] = true
		} else {
			st.indexes[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return st, fmt.Errorf("inspect schema: %w", err)
	}
	rows.Close()
	if len(st.tables) == 0 {
		st.empty = true
		return st, nil
	}
	if !st.tables["jobs"] {
		return st, fmt.Errorf("%w: it has tables but no jobs table", ErrNotAStoreDatabase)
	}
	st.columns, err = jobsTableColumns(q)
	return st, err
}

// jobsTableColumns returns the jobs table's column names.
func jobsTableColumns(q queryer) (map[string]bool, error) {
	rows, err := q.Query(`SELECT name FROM pragma_table_info('jobs')`)
	if err != nil {
		return nil, fmt.Errorf("inspect jobs table: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("inspect jobs table: %w", err)
		}
		out[name] = true
	}
	return out, rows.Err()
}

// migrationStep is one schema change and the statement that makes it.
type migrationStep struct {
	describe string
	stmt     string
}

// planMigration lists the changes that bring an existing database to the current schema, in
// order; none for a database already current. It refuses a database it cannot migrate safely: a
// jobs table missing one of the base columns, or holding both session id columns.
func planMigration(st schemaState) ([]migrationStep, error) {
	cols := st.columns
	if cols[legacySessionColumn] && cols["session_id"] {
		return nil, ErrAmbiguousSessionColumn
	}
	var steps []migrationStep
	for _, c := range baseColumns {
		switch {
		case cols[c.name]:
		case c.name == "session_id" && cols[legacySessionColumn]:
			steps = append(steps, migrationStep{
				describe: "rename column jobs." + legacySessionColumn + " to session_id",
				stmt:     `ALTER TABLE jobs RENAME COLUMN ` + legacySessionColumn + ` TO session_id`,
			})
		case c.name == "session_id":
			steps = append(steps, migrationStep{describe: "add column jobs.session_id", stmt: `ALTER TABLE jobs ADD COLUMN session_id TEXT`})
		default:
			return nil, fmt.Errorf("%w: its jobs table has no %s column", ErrNotAStoreDatabase, c.name)
		}
	}
	for _, c := range addedColumns {
		if !cols[c.name] {
			steps = append(steps, migrationStep{describe: "add column jobs." + c.name, stmt: `ALTER TABLE jobs ADD COLUMN ` + c.name + ` ` + c.decl})
		}
	}
	if !st.tables["event_outbox"] {
		steps = append(steps, migrationStep{describe: "create table event_outbox", stmt: outboxTableDDL})
	}
	if !st.tables["backend_drains"] {
		steps = append(steps, migrationStep{describe: "create table backend_drains", stmt: drainsTableDDL})
	}
	if st.indexes[globalIdempotencyIndex] {
		steps = append(steps, migrationStep{describe: "drop index " + globalIdempotencyIndex, stmt: `DROP INDEX ` + globalIdempotencyIndex})
	}
	if st.indexes[textWindowIndex] {
		steps = append(steps, migrationStep{describe: "drop index " + textWindowIndex, stmt: `DROP INDEX ` + textWindowIndex})
	}
	for _, ix := range plainIndexes {
		if !st.indexes[ix.name] {
			steps = append(steps, migrationStep{describe: "create index " + ix.name, stmt: ix.ddl})
		}
	}
	if !st.indexes[retryOfIndex] && !st.indexes[retryOfFallbackIndex] {
		steps = append(steps, migrationStep{describe: "create index " + retryOfIndex}) // ensureRetryOfIndex
	}
	return steps, nil
}

// execer is *sql.DB, *sql.Conn or *sql.Tx.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// createSchema creates every table and index of a new database.
func createSchema(tx execer) error {
	stmts := []string{jobsTableDDL(), outboxTableDDL, drainsTableDDL}
	for _, ix := range plainIndexes {
		stmts = append(stmts, ix.ddl)
	}
	for _, s := range stmts {
		if _, err := tx.Exec(s); err != nil {
			return fmt.Errorf("create schema: %w", err)
		}
	}
	return ensureRetryOfIndex(tx)
}

// afterMigrationStep, when set (tests only), runs after each step; an error fails the migration
// there, as a failing statement would.
var afterMigrationStep func(describe string) error

// applyMigration runs steps in tx.
func applyMigration(tx execer, steps []migrationStep) error {
	for _, s := range steps {
		var err error
		if s.stmt == "" {
			err = ensureRetryOfIndex(tx)
		} else {
			_, err = tx.Exec(s.stmt)
		}
		if err == nil && afterMigrationStep != nil {
			err = afterMigrationStep(s.describe)
		}
		if err != nil {
			return fmt.Errorf("migrate schema: %s: %w", s.describe, err)
		}
	}
	return nil
}

// ensureRetryOfIndex makes retry_of_run_id unique: one retry per run. A database that already
// holds two retries of one run (an earlier controller's two automatic retries could both
// fire) cannot take the unique index; it gets a plain one and a warning, and insertJobTx's check
// still refuses every new second retry.
func ensureRetryOfIndex(tx execer) error {
	_, err := tx.Exec(retryOfIndexDDL)
	if err == nil {
		return nil
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unique") {
		return fmt.Errorf("create %s: %w", retryOfIndex, err)
	}
	log.Printf("store: existing rows hold more than one retry of a run, so retry_of_run_id gets a non-unique index (one retry per run is still enforced on insert): %v", err)
	if _, err := tx.Exec(retryOfFallbackIndexDDL); err != nil {
		return fmt.Errorf("create %s: %w", retryOfFallbackIndex, err)
	}
	return nil
}
