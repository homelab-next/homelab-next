// SPDX-License-Identifier: Apache-2.0

package store

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The submit window's count is bounded by time, not by every job the submitter ever sent: its
// query, as checkLimits runs it, searches an index on the submitter and julianday(created_at), with
// a range on the second.
func TestSubmitWindow_CountSearchesByTime(t *testing.T) {
	s := openTest(t)
	rows, err := s.db.Query(`EXPLAIN QUERY PLAN `+windowCountQuery,
		"alice", time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	joined := strings.Join(plan, "; ")
	if !strings.Contains(joined, "USING") || !strings.Contains(joined, "<expr>=? AND <expr>>?") {
		t.Fatalf("the window count is not bounded by time: plan %q", joined)
	}
}

// A database that has the earlier text-keyed window index migrates to the expression index.
func TestMigrate_ReplacesTheTextWindowIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orch.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP INDEX idx_jobs_submitter_created_jd`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE INDEX idx_jobs_submitter_created ON jobs(COALESCE(submitted_by, ''), created_at)`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	steps, err := PendingMigrations(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(steps, "drop index idx_jobs_submitter_created") || !slices.Contains(steps, "create index idx_jobs_submitter_created_jd") {
		t.Fatalf("steps = %v", steps)
	}
	m, _ := migrateWithBackup(t, path)
	var n int
	m.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = ?`, "idx_jobs_submitter_created").Scan(&n)
	if n != 0 {
		t.Error("the text window index survived the migration")
	}
}
