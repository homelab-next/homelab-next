// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A migration interrupted by a crash, at each point it can stop, resumes cleanly (ADR-0026 stage
// 2, PR 2.8's restart-during-migration case):
//   - in the backup: what it left (a partial file) is never taken for a backup, the database is
//     unchanged, and a new backup path migrates it;
//   - in the migration: the transaction never committed, so the database is as it was and the
//     backup still verifies against it.
func TestMigrate_ACrashInTheBackupOrTheMigrationResumesCleanly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orch.db")
	fixtureDB(t, path, "schema-v1.sql", v1Rows...)
	before, _ := PendingMigrations(path)
	dir := t.TempDir()

	// the backup crashed half way: a partial file at the backup's path
	partial := filepath.Join(dir, "orch.db.bak")
	if err := os.WriteFile(partial, []byte("SQLite format 3\x00 cut short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := BackupForMigration(path, partial); err == nil {
		t.Fatal("a backup over a partial file was taken")
	}
	if _, err := OpenWith(path, Options{MigrationBackup: partial}); !errors.Is(err, ErrBackupMismatch) {
		t.Fatalf("a partial backup = %v, want ErrBackupMismatch", err)
	}
	if after, _ := PendingMigrations(path); strings.Join(after, ";") != strings.Join(before, ";") {
		t.Fatalf("a refused partial backup changed the database: %v", after)
	}

	// the migration crashed in its transaction (a step failing after the rename stands in for it)
	backup := filepath.Join(dir, "orch.db.bak2")
	if err := BackupForMigration(path, backup); err != nil {
		t.Fatal(err)
	}
	afterMigrationStep = func(step string) error {
		if strings.HasPrefix(step, "add column") {
			return errors.New("the process died here")
		}
		return nil
	}
	_, err := OpenWith(path, Options{MigrationBackup: backup})
	afterMigrationStep = nil
	if err == nil {
		t.Fatal("the interrupted migration reported success")
	}
	if err := VerifyBackup(path, backup); err != nil {
		t.Fatalf("after the interrupted migration the backup no longer matches the database: %v", err)
	}
	// the restart: the same backup, the whole migration, once
	s, err := OpenWith(path, Options{MigrationBackup: backup})
	if err != nil {
		t.Fatalf("the resumed migration: %v", err)
	}
	defer s.Close()
	if steps, _ := PendingMigrations(path); len(steps) != 0 {
		t.Fatalf("still pending after the resumed migration: %v", steps)
	}
}
