// SPDX-License-Identifier: Apache-2.0

package store

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeRaw(t *testing.T, path string, stmts ...string) {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, s := range stmts {
		if _, err := raw.Exec(s); err != nil {
			t.Fatalf("%q: %v", s, err)
		}
	}
	ownerOnly(t, path)
}

// oldDB is a database that needs a migration, with two rows.
func oldDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "orch.db")
	fixtureDB(t, path, "schema-v1.sql", v1Rows...)
	return path
}

// The backup is owner-only, opens, passes integrity_check and holds the database's rows; it never
// overwrites a file, and taking it changes nothing in the database.
func TestBackupForMigration_WritesAVerifiedOwnerOnlyCopy(t *testing.T) {
	path := oldDB(t)
	before, _ := PendingMigrations(path)
	backup := filepath.Join(t.TempDir(), "orch.db.bak")
	if err := BackupForMigration(path, backup); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(backup)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %v, %v; want 0600", fi.Mode().Perm(), err)
	}
	if err := VerifyBackup(path, backup); err != nil {
		t.Errorf("VerifyBackup: %v", err)
	}
	raw, _ := sql.Open("sqlite", "file:"+backup+"?mode=ro")
	defer raw.Close()
	var sess string
	if err := raw.QueryRow(`SELECT hermes_session_id FROM jobs WHERE run_id = 'old-run'`).Scan(&sess); err != nil || sess != "sess-old" {
		t.Errorf("backup row = %q, %v", sess, err)
	}
	if after, _ := PendingMigrations(path); len(after) != len(before) {
		t.Errorf("taking the backup changed the database: %v -> %v", before, after)
	}
	if err := BackupForMigration(path, backup); err == nil {
		t.Error("an existing backup was overwritten")
	}
	if err := BackupForMigration(filepath.Join(t.TempDir(), "absent.db"), filepath.Join(t.TempDir(), "x.bak")); err == nil {
		t.Error("a backup of a missing database was written")
	}
}

func TestBackup_RefusesTheDatabaseItsFilesAndSpecialPaths(t *testing.T) {
	path := oldDB(t)
	for _, b := range []string{path, path + "-wal", path + "-shm", path + "-journal", path + ".lock", "", filepath.Join(t.TempDir(), "a%41.bak")} {
		if err := BackupForMigration(path, b); err == nil {
			t.Errorf("backup path %q accepted", b)
		}
	}
	if steps, _ := PendingMigrations(path); len(steps) == 0 {
		t.Fatal("the database was migrated")
	}
}

// A backup that no longer matches the database (a job written after it) is refused by Open,
// which then leaves the database unmigrated; a fresh backup is accepted.
func TestOpenWith_RefusesAStaleBackupAndChangesNothing(t *testing.T) {
	path := oldDB(t)
	backup := filepath.Join(t.TempDir(), "orch.db.bak")
	if err := BackupForMigration(path, backup); err != nil {
		t.Fatal(err)
	}
	writeRaw(t, path, `INSERT INTO jobs (run_id, agent_key, priority, seq, state, created_at) VALUES ('later', 'watcher', 1, 3, 'queued', '2026-09-03T00:00:00Z')`)
	if err := VerifyBackup(path, backup); !errors.Is(err, ErrBackupMismatch) {
		t.Errorf("VerifyBackup of a stale backup = %v", err)
	}
	if _, err := OpenWith(path, Options{MigrationBackup: backup}); !errors.Is(err, ErrBackupMismatch) {
		t.Fatalf("OpenWith a stale backup = %v, want ErrBackupMismatch", err)
	}
	if steps, _ := PendingMigrations(path); len(steps) == 0 {
		t.Fatal("a refused migration changed the database")
	}
	fresh := filepath.Join(t.TempDir(), "orch.db.bak2")
	if err := BackupForMigration(path, fresh); err != nil {
		t.Fatal(err)
	}
	s, err := OpenWith(path, Options{MigrationBackup: fresh})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.GetJob("later"); err != nil {
		t.Error(err)
	}
}

// A backup that does not open or is damaged, a missing one, one readable by others when the
// database is not, and a symbolic link to a good backup are all refused.
func TestVerifyBackup_Refusals(t *testing.T) {
	path := oldDB(t)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "good.bak")
	if err := BackupForMigration(path, good); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}

	header := filepath.Join(dir, "header.bak")
	bad := append([]byte(nil), data...)
	copy(bad, "not a database at all")
	if err := os.WriteFile(header, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	pages := filepath.Join(dir, "pages.bak")
	bad = append([]byte(nil), data...)
	for i := 4096; i < len(bad); i++ { // every page after the first
		bad[i] ^= 0xA5
	}
	if err := os.WriteFile(pages, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	wide := filepath.Join(dir, "wide.bak")
	if err := os.WriteFile(wide, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wide, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.bak")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]string{"header": header, "pages": pages, "wide": wide, "link": link, "missing": filepath.Join(dir, "missing.bak")} {
		if err := VerifyBackup(path, b); !errors.Is(err, ErrBackupMismatch) {
			t.Errorf("%s: %v, want ErrBackupMismatch", name, err)
		}
		if _, err := OpenWith(path, Options{MigrationBackup: b}); err == nil {
			t.Errorf("%s: OpenWith migrated behind it", name)
		}
	}
	if err := VerifyBackup(path, good); err != nil {
		t.Errorf("the good backup: %v", err)
	}
}
