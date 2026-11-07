// SPDX-License-Identifier: Apache-2.0

package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// openTest opens a new database in the test's temporary directory, closed at cleanup.
func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "orch.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// queued is a queued job of agent with run id and idempotency key id.
func queued(id, agent string) *Job {
	return &Job{RunID: id, AgentKey: agent, Priority: 50, State: StateQueued, IdempotencyKey: "idem-" + id, CreatedAt: time.Now().UTC()}
}

// mkJob creates a job directly in state (CreateJob writes the state it is given).
func mkJob(t *testing.T, s *Store, id, agent string, state State) {
	t.Helper()
	j := queued(id, agent)
	j.State = state
	if err := s.CreateJob(j); err != nil {
		t.Fatalf("CreateJob %s: %v", id, err)
	}
}

// fixtureDB builds a database at path from a frozen schema under testdata/ and runs the given
// statements on it, with the plain driver: nothing of the store touches it.
func fixtureDB(t *testing.T, path, schemaFile string, stmts ...string) {
	t.Helper()
	ddl, err := os.ReadFile(filepath.Join("testdata", schemaFile))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(string(ddl)); err != nil {
		t.Fatalf("%s: %v", schemaFile, err)
	}
	for _, s := range stmts {
		if _, err := raw.Exec(s); err != nil {
			t.Fatalf("fixture statement %q: %v", s, err)
		}
	}
	ownerOnly(t, path)
}

// ownerOnly makes a database the plain driver created under the test's umask owner-only, as the
// store requires.
func ownerOnly(t *testing.T, path string) {
	t.Helper()
	for _, side := range []string{"", "-wal", "-shm", "-journal"} {
		if err := os.Chmod(path+side, 0o600); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
}

func intp(n int) *int           { return &n }
func floatp(f float64) *float64 { return &f }
