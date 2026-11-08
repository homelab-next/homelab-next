// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// v1Rows are rows as the first schema held them: one with every optional text column NULL, as
// no version of this store writes, and one with a session id.
var v1Rows = []string{
	`INSERT INTO jobs (run_id, agent_key, priority, seq, state, created_at) VALUES ('nulls', 'watcher', 50, 1, 'done', '2026-09-01T00:00:00Z')`,
	`INSERT INTO jobs (run_id, agent_key, profile_id, profile_revision, priority, seq, state, local_failed_reason, hermes_session_id, idempotency_key,
		created_at, started_at, finished_at, result_path, evidence_refs)
		VALUES ('old-run', 'watcher', 'watcher-v1', 'rev', 50, 2, 'failed', 'stalled', 'sess-old', 'evt-old',
		'2026-09-02T00:00:00Z', '2026-09-02T00:00:01Z', '2026-09-02T00:01:00Z', 'out/old-run.md', 'ref-1')`,
}

func columnSet(t *testing.T, s *Store) []string {
	t.Helper()
	cols, err := jobsTableColumns(s.db)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for c := range cols {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func freshColumns(t *testing.T) []string {
	t.Helper()
	return columnSet(t, openTest(t))
}

// migrateWithBackup checks Open refuses the database without a backup, takes one and opens with
// it. It returns the store and the backup's path.
func migrateWithBackup(t *testing.T, path string) (*Store, string) {
	t.Helper()
	if s, err := Open(path); !errors.Is(err, ErrBackupRequired) {
		if s != nil {
			s.Close()
		}
		t.Fatalf("Open without a backup = %v, want ErrBackupRequired", err)
	}
	backup := filepath.Join(t.TempDir(), "orch.db.bak")
	if err := BackupForMigration(path, backup); err != nil {
		t.Fatalf("BackupForMigration: %v", err)
	}
	s, err := OpenWith(path, Options{MigrationBackup: backup})
	if err != nil {
		t.Fatalf("OpenWith the backup: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, backup
}

// The first schema migrates: the session id column is renamed with its values kept, every added
// column and the missing tables and indexes appear (task_description among them), old rows read
// back with NULL as empty, the result has the new database's columns, a second Open finds nothing
// to do and needs no backup, and the backup still holds the old schema.
func TestMigrate_FromTheFirstSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orch.db")
	fixtureDB(t, path, "schema-v1.sql", v1Rows...)
	steps, err := PendingMigrations(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"rename column jobs.hermes_session_id to session_id", "add column jobs.task_description",
		"add column jobs.finished_pending", "create table event_outbox", "create table backend_drains", "create index idx_jobs_seq", "create index idx_jobs_retry_of"} {
		if !slices.Contains(steps, want) {
			t.Errorf("pending migrations lack %q: %v", want, steps)
		}
	}
	if slices.Contains(steps, "create index idx_jobs_state") {
		t.Errorf("an index the database has is listed: %v", steps)
	}
	s, backup := migrateWithBackup(t, path)
	j, err := s.GetJob("old-run")
	if err != nil {
		t.Fatal(err)
	}
	if j.SessionID != "sess-old" || j.IdempotencyKey != "evt-old" || j.LocalFailedReason != "stalled" || j.ResultPath != "out/old-run.md" ||
		j.FinishedAt == nil || j.TaskDescription != "" || j.Usage.Known() || j.FailureReason() != FailureUnknown {
		t.Errorf("migrated row = %+v", j)
	}
	if n, err := s.GetJob("nulls"); err != nil || n.ProfileID != "" || n.SessionID != "" || n.StartedAt != nil {
		t.Errorf("a row of NULLs = %+v, %v", n, err)
	}
	if got, want := columnSet(t, s), freshColumns(t); !slices.Equal(got, want) {
		t.Errorf("migrated columns %v\nnew database's %v", got, want)
	}
	// the migrated database works as a new one does
	nj := queued("new", "watcher")
	nj.TaskDescription = "written after the migration"
	if err := s.CreateJob(nj); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateJob(queued("dup", "watcher")); err != nil {
		t.Fatal(err)
	}
	dup := queued("dup2", "watcher")
	dup.IdempotencyKey = "evt-old"
	if err := s.CreateJob(dup); !errors.Is(err, ErrDuplicateIdempotencyKey) {
		t.Errorf("an old row's key is not held after migration: %v", err)
	}
	s.Close()
	if steps, err := PendingMigrations(path); err != nil || len(steps) != 0 {
		t.Errorf("after migration: pending %v, %v", steps, err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatalf("second Open, no backup: %v", err)
	}
	if j, _ := again.GetJob("new"); j.TaskDescription != "written after the migration" {
		t.Errorf("task = %q", j.TaskDescription)
	}
	again.Close()
	bs, err := PendingMigrations(backup)
	if err != nil || !slices.Contains(bs, "rename column jobs.hermes_session_id to session_id") {
		t.Errorf("the backup is not the old database: %v, %v", bs, err)
	}
}

// The last schema before the rename (every column added, the passthrough's request_body among
// them) migrates by the rename, the idempotency index's replacement and the submitter bounds'
// indexes alone; request_body stays, with its values, and is never read.
func TestMigrate_FromTheLastSchemaBeforeTheRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orch.db")
	fixtureDB(t, path, "schema-before-session-id.sql",
		`INSERT INTO jobs (run_id, agent_key, priority, seq, state, created_at, hermes_session_id, request_body, response_body, model, input_tokens, retry_of_run_id, resubmits)
			VALUES ('r1', 'watcher', 1, 1, 'done', '2026-10-01T00:00:00Z', 'sess-1', '{"messages":[]}', 'the answer', 'example-model-8b', 12, NULL, 0)`,
		`INSERT INTO event_outbox (event_id, body, created_at) VALUES ('evt-1', '{}', '2026-10-01T00:00:00Z')`,
	)
	steps, err := PendingMigrations(path)
	if want := "[rename column jobs.hermes_session_id to session_id add column jobs.task_sha256 drop index idx_jobs_idempotency create index idx_jobs_idempotency_owner create index idx_jobs_submitter_created_jd create index idx_jobs_submitter_state]"; err != nil || fmt.Sprint(steps) != want {
		t.Fatalf("pending = %v, %v; want the rename, the task digest, the key index's replacement and the submitter indexes alone", steps, err)
	}
	s, _ := migrateWithBackup(t, path)
	j, err := s.GetJob("r1")
	if err != nil || j.SessionID != "sess-1" || j.ResponseBody != "the answer" || j.Model != "example-model-8b" || j.InputTokens != 12 {
		t.Fatalf("migrated row = %+v, %v", j, err)
	}
	var body string
	if err := s.db.QueryRow(`SELECT request_body FROM jobs WHERE run_id = 'r1'`).Scan(&body); err != nil || body != `{"messages":[]}` {
		t.Errorf("the retired column lost its value: %q, %v", body, err)
	}
	got, want := columnSet(t, s), freshColumns(t)
	var extra []string
	for _, c := range got {
		if !slices.Contains(want, c) {
			extra = append(extra, c)
		}
	}
	if fmt.Sprint(extra) != fmt.Sprint(retiredColumns()) {
		t.Errorf("columns beyond a new database's: %v, want only %v", extra, retiredColumns())
	}
	if n, _ := s.OutboxLen(); n != 1 {
		t.Errorf("the outbox lost its event: %d", n)
	}
}

// A jobs table with both session id columns is refused, with or without a backup, and left as
// it is.
func TestMigrate_RefusesBothSessionColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orch.db")
	fixtureDB(t, path, "schema-before-session-id.sql", `ALTER TABLE jobs ADD COLUMN session_id TEXT`)
	if _, err := PendingMigrations(path); !errors.Is(err, ErrAmbiguousSessionColumn) {
		t.Errorf("PendingMigrations = %v", err)
	}
	if _, err := Open(path); !errors.Is(err, ErrAmbiguousSessionColumn) {
		t.Errorf("Open = %v, want ErrAmbiguousSessionColumn", err)
	}
	backup := filepath.Join(t.TempDir(), "orch.db.bak")
	if err := BackupForMigration(path, backup); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWith(path, Options{MigrationBackup: backup}); !errors.Is(err, ErrAmbiguousSessionColumn) {
		t.Errorf("OpenWith a backup = %v, want ErrAmbiguousSessionColumn", err)
	}
	if err := VerifyBackup(path, backup); err != nil {
		t.Errorf("the refused database changed: %v", err)
	}
}

// A file that is not this store's database is refused, never adopted.
func TestMigrate_RefusesAForeignDatabase(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "other.db")
	writeRaw(t, other, `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`)
	if _, err := Open(other); !errors.Is(err, ErrNotAStoreDatabase) {
		t.Errorf("a database without a jobs table: %v", err)
	}
	thin := filepath.Join(dir, "thin.db")
	writeRaw(t, thin, `CREATE TABLE jobs (run_id TEXT PRIMARY KEY, agent_key TEXT NOT NULL)`)
	if _, err := Open(thin); !errors.Is(err, ErrNotAStoreDatabase) {
		t.Errorf("a jobs table without the base columns: %v", err)
	}
	if steps, err := PendingMigrations(filepath.Join(dir, "absent.db")); err != nil || steps != nil {
		t.Errorf("a missing file: %v, %v", steps, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "absent.db")); !os.IsNotExist(err) {
		t.Error("PendingMigrations created the file")
	}
}

// The new database's columns are exactly the base and added lists: the migration and the
// CREATE TABLE cannot drift apart.
func TestSchema_NewDatabaseHasEveryListedColumn(t *testing.T) {
	var want []string
	for _, c := range append(append([]column(nil), baseColumns...), addedColumns...) {
		want = append(want, c.name)
	}
	sort.Strings(want)
	if got := freshColumns(t); !slices.Equal(got, want) {
		t.Errorf("columns %v, want %v", got, want)
	}
	for _, c := range addedColumns {
		if strings.Contains(strings.ToUpper(c.decl), "NOT NULL") || strings.Contains(strings.ToUpper(c.decl), "DEFAULT") {
			t.Errorf("added column %s is %q: an added column must be nullable with no default", c.name, c.decl)
		}
	}
	if strings.Contains(jobsTableDDL(), legacySessionColumn) {
		t.Error("a new database names the old session column")
	}
}
