// SPDX-License-Identifier: Apache-2.0

package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A backup that is the database, or one of its side files, under another name is refused: a
// hard link, a path through a symbolic link to the database's directory; and so is a backup with
// a second link.
func TestVerifyBackup_RefusesAliases(t *testing.T) {
	path := oldDB(t)
	dbDir := filepath.Dir(path)
	other := t.TempDir()
	hard := filepath.Join(dbDir, "hard.bak")
	if err := os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(other, "via")
	if err := os.Symlink(dbDir, dirLink); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(other, "good.bak")
	if err := BackupForMigration(path, good); err != nil {
		t.Fatal(err)
	}
	twice := filepath.Join(other, "twice.bak")
	if err := os.Link(good, twice); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]string{"hard link": hard, "linked directory": filepath.Join(dirLink, "orch.db"), "second link": twice} {
		if err := VerifyBackup(path, b); !errors.Is(err, ErrBackupMismatch) {
			t.Errorf("%s: VerifyBackup = %v, want ErrBackupMismatch", name, err)
		}
		if s, err := OpenWith(path, Options{MigrationBackup: b}); err == nil {
			s.Close()
			t.Errorf("%s: OpenWith migrated behind it", name)
		}
	}
	if steps, _ := PendingMigrations(path); len(steps) == 0 {
		t.Fatal("the database was migrated behind an alias")
	}
}

// A backup directory its group or others can write is refused, for writing and for verifying.
func TestBackup_RefusesASharedDirectory(t *testing.T) {
	path := oldDB(t)
	shared := t.TempDir()
	good := filepath.Join(shared, "good.bak")
	if err := BackupForMigration(path, good); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := BackupForMigration(path, filepath.Join(shared, "new.bak")); !errors.Is(err, ErrBackupMismatch) {
		t.Errorf("BackupForMigration into a group-writable directory = %v", err)
	}
	if _, err := os.Stat(filepath.Join(shared, "new.bak")); !os.IsNotExist(err) {
		t.Error("a backup was written into the shared directory")
	}
	if err := VerifyBackup(path, good); !errors.Is(err, ErrBackupMismatch) {
		t.Errorf("VerifyBackup in a group-writable directory = %v", err)
	}
}

// The file verified must be the file the backup created: another file at the path is refused.
func TestVerifyBackup_PinnedFile(t *testing.T) {
	path := oldDB(t)
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.bak"), filepath.Join(dir, "b.bak")
	for _, p := range []string{a, b} {
		if err := BackupForMigration(path, p); err != nil {
			t.Fatal(err)
		}
	}
	fa, _ := os.Lstat(a)
	db, err := openPlain(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := verifyBackupAgainst(db, path, b, fa); !errors.Is(err, ErrBackupMismatch) {
		t.Errorf("a different file at the path = %v, want ErrBackupMismatch", err)
	}
	if err := verifyBackupAgainst(db, path, a, fa); err != nil {
		t.Errorf("the pinned file itself: %v", err)
	}
}

// Relative paths, even ones spelt like a file: URI, are made absolute: the backup lands at the
// path named and no copy appears anywhere else; Open of such a path creates that file.
func TestBackup_FilePrefixIsAPathNotAURI(t *testing.T) {
	path := oldDB(t)
	cwd := t.TempDir()
	t.Chdir(cwd)
	if err := BackupForMigration(path, "file:x.bak"); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(cwd)
	if len(entries) != 1 || entries[0].Name() != "file:x.bak" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("the directory holds %v, want only file:x.bak", names)
	}
	if err := VerifyBackup(path, "file:x.bak"); err != nil {
		t.Errorf("VerifyBackup: %v", err)
	}
	s, err := Open("file:new.db")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := os.Stat(filepath.Join(cwd, "file:new.db")); err != nil {
		t.Errorf("Open of a file:-spelt path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cwd, "new.db")); !os.IsNotExist(err) {
		t.Error("Open read the path as a URI")
	}
}

// VerifyBackup and PendingMigrations never create a missing database.
func TestVerifyBackup_DoesNotCreateAMissingDatabase(t *testing.T) {
	path := oldDB(t)
	good := filepath.Join(t.TempDir(), "good.bak")
	if err := BackupForMigration(path, good); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "absent.db")
	if err := VerifyBackup(missing, good); err == nil {
		t.Error("VerifyBackup against a missing database passed")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Error("VerifyBackup created the database")
	}
}

// A new database and its -wal and -shm files are owner-only whatever the umask; an existing
// database readable by others is refused unless AllowSharedPermissions.
func TestOpen_DatabaseIsOwnerOnly(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	path := filepath.Join(t.TempDir(), "orch.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateJob(queued("r", "agent-a")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s is %v, want 0600", filepath.Base(p), fi.Mode().Perm())
		}
	}
	s.Close()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, ErrDatabasePermissions) {
		t.Fatalf("a 0644 database: %v, want ErrDatabasePermissions", err)
	}
	s, err = OpenWith(path, Options{AllowSharedPermissions: true})
	if err != nil {
		t.Fatalf("AllowSharedPermissions: %v", err)
	}
	s.Close()
}

// OpenWith holds the instance lock for the Store's life, through any spelling of the path, and
// Close releases it. A lock the caller gives must be held and this database's: a released one, or
// another database's, is refused, and Close leaves a given lock held.
func TestOpenWith_HoldsTheInstanceLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "orch.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, ErrInstanceLocked) {
		t.Errorf("a second Open = %v, want ErrInstanceLocked", err)
	}
	link := filepath.Join(t.TempDir(), "via")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(link, "orch.db")); !errors.Is(err, ErrInstanceLocked) {
		t.Errorf("Open through a linked directory = %v, want ErrInstanceLocked", err)
	}
	if _, err := LockInstance(filepath.Join(link, "orch.db")); !errors.Is(err, ErrInstanceLocked) {
		t.Errorf("LockInstance through a linked directory = %v, want ErrInstanceLocked", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := LockInstance(filepath.Join(dir, "other.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Release()
	if _, err := OpenWith(path, Options{Lock: other}); err == nil || !strings.Contains(err.Error(), "not this database's") {
		t.Errorf("another database's lock = %v", err)
	}
	lock, err := LockInstance(filepath.Join(link, "orch.db"))
	if err != nil {
		t.Fatal(err)
	}
	s, err = OpenWith(path, Options{Lock: lock})
	if err != nil {
		t.Fatalf("OpenWith a held lock through another spelling: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := LockInstance(path); !errors.Is(err, ErrInstanceLocked) {
		t.Errorf("Close released the caller's lock: LockInstance = %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWith(path, Options{Lock: lock}); err == nil || !strings.Contains(err.Error(), "released") {
		t.Errorf("a released lock = %v", err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	s.Close()
}

// An idempotency key is scoped to its submitter: another submitter may use it, the same one may
// not, a replayed resubmit finds its run under the parent's owner, and a key is bounded.
func TestIdempotencyKey_ScopedToTheSubmitter(t *testing.T) {
	s := openTest(t)
	mk := func(id, owner, key string) error {
		j := queued(id, "agent-a")
		j.SubmittedBy, j.IdempotencyKey = owner, key
		return s.CreateJob(j)
	}
	if err := mk("a1", "alice", "k"); err != nil {
		t.Fatal(err)
	}
	if err := mk("b1", "bob", "k"); err != nil {
		t.Fatalf("another submitter's key: %v", err)
	}
	if err := mk("n1", "", "k"); err != nil {
		t.Fatalf("an unowned job's key: %v", err)
	}
	for _, owner := range []string{"alice", "bob", ""} {
		if err := mk("dup-"+owner, owner, "k"); !errors.Is(err, ErrDuplicateIdempotencyKey) {
			t.Errorf("%q again: %v", owner, err)
		}
	}
	if j, err := s.FindByIdempotencyKey("bob", "k"); err != nil || j.RunID != "b1" {
		t.Errorf("FindByIdempotencyKey(bob) = %v, %v", j, err)
	}
	if _, err := s.FindByIdempotencyKey("carol", "k"); !errors.Is(err, ErrNotFound) {
		t.Errorf("FindByIdempotencyKey(carol) = %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO jobs (run_id, agent_key, priority, seq, state, created_at, submitted_by, idempotency_key) VALUES ('raw', 'a', 1, 99, 'queued', '2026-01-01T00:00:00Z', 'alice', 'k')`); err == nil {
		t.Error("the unique index let a second (alice, k) in")
	}
	if err := mk("long", "alice", strings.Repeat("x", MaxIdempotencyKeyLen+1)); !errors.Is(err, ErrIdempotencyKeyTooLong) {
		t.Errorf("a long key: %v", err)
	}
	if err := mk("max", "alice", strings.Repeat("x", MaxIdempotencyKeyLen)); err != nil {
		t.Errorf("a key of the maximum length: %v", err)
	}

	failedRun(t, s, "p", "alice", StateFailed, FailureCapacity)
	admin := ResubmitCheck{MayAccess: func(string) bool { return true }}
	if _, err := resubmit(s, "p", "evt-1", "admin", admin); err != nil {
		t.Fatal(err)
	}
	if _, err := resubmit(s, "p", "evt-1", "admin", admin); !errors.Is(err, ErrDuplicateIdempotencyKey) {
		t.Errorf("the admin's replayed resubmit = %v, want ErrDuplicateIdempotencyKey", err)
	}
	if j, err := s.FindByIdempotencyKey("alice", "evt-1"); err != nil || j.RetryOfRunID != "p" {
		t.Errorf("the resubmit is not under its owner's key: %v, %v", j, err)
	}
}

// A migrated database scopes keys too: the old global index is replaced.
func TestMigrate_ScopesIdempotencyKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orch.db")
	fixtureDB(t, path, "schema-v1.sql", v1Rows...)
	s, _ := migrateWithBackup(t, path)
	j := queued("other-owner", "watcher")
	j.SubmittedBy, j.IdempotencyKey = "bob", "evt-old"
	if err := s.CreateJob(j); err != nil {
		t.Errorf("another submitter's use of an old key: %v", err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = ?`, globalIdempotencyIndex).Scan(&n)
	if n != 0 {
		t.Error("the global key index survived the migration")
	}
}

// A step failing after the rename rolls the whole migration back: the database keeps its old
// schema and rows, and migrates cleanly afterwards.
func TestMigrate_AFailingStepRollsEverythingBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orch.db")
	fixtureDB(t, path, "schema-v1.sql", v1Rows...)
	before, _ := PendingMigrations(path)
	backup := filepath.Join(t.TempDir(), "orch.db.bak")
	if err := BackupForMigration(path, backup); err != nil {
		t.Fatal(err)
	}
	renamed := false
	afterMigrationStep = func(step string) error {
		if strings.HasPrefix(step, "rename column") {
			renamed = true
		}
		if step == "add column jobs.model" {
			return errors.New("injected failure")
		}
		return nil
	}
	_, err := OpenWith(path, Options{MigrationBackup: backup})
	afterMigrationStep = nil
	if err == nil || !strings.Contains(err.Error(), "injected failure") || !renamed {
		t.Fatalf("OpenWith = %v (renamed %v), want the injected failure after the rename", err, renamed)
	}
	if after, _ := PendingMigrations(path); strings.Join(after, ";") != strings.Join(before, ";") {
		t.Fatalf("a failed migration left changes: pending %v, was %v", after, before)
	}
	if err := VerifyBackup(path, backup); err != nil {
		t.Errorf("the database no longer equals its backup: %v", err)
	}
	s, err := OpenWith(path, Options{MigrationBackup: backup})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if j, err := s.GetJob("old-run"); err != nil || j.SessionID != "sess-old" {
		t.Errorf("after the retry: %v, %v", j, err)
	}
}

// A backup taken while another connection holds frames in the write-ahead log holds those rows.
func TestBackupForMigration_IncludesWALFrames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orch.db")
	fixtureDB(t, path, "schema-v1.sql")
	raw, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetMaxOpenConns(1)
	for _, st := range v1Rows {
		if _, err := raw.Exec(st); err != nil {
			t.Fatal(err)
		}
	}
	ownerOnly(t, path)
	if fi, err := os.Stat(path + "-wal"); err != nil || fi.Size() == 0 {
		t.Fatalf("no frames in the write-ahead log: %v", err)
	}
	backup := filepath.Join(t.TempDir(), "orch.db.bak")
	if err := BackupForMigration(path, backup); err != nil {
		t.Fatal(err)
	}
	b, _ := sql.Open("sqlite", "file:"+backup+"?mode=ro")
	defer b.Close()
	var n int
	if err := b.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&n); err != nil || n != len(v1Rows) {
		t.Fatalf("backup rows = %d, %v; want %d", n, err, len(v1Rows))
	}
}

// The frozen fixtures never change: a later schema is a new fixture.
func TestFixturesAreFrozen(t *testing.T) {
	for name, want := range map[string]string{
		"schema-v1.sql":                frozenV1SHA256,
		"schema-before-session-id.sql": frozenBeforeRenameSHA256,
	} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("testdata/%s sha256 %s, frozen at %s: add a new fixture instead", name, got, want)
		}
	}
}

// The outbox's drop count moves only when the transaction that dropped commits.
func TestOutbox_DropsCountOnlyOnCommit(t *testing.T) {
	s := openTest(t)
	s.EnableOutbox(testBuilder, 1, nil)
	if err := s.EnqueueEvent("first", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	mkJob(t, s, "good", "agent-a", StateRunning)
	// a row no scan can read (text in the priority column) makes the second enqueue fail,
	// after the first one has trimmed the outbox
	if _, err := s.db.Exec(`INSERT INTO jobs (run_id, agent_key, priority, seq, state, created_at) VALUES ('bad', 'a', 'not-a-number', 99, 'running', ?)`,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReconcileOrphans(); err == nil {
		t.Fatal("reconciliation over an unreadable row succeeded")
	}
	if s.OutboxDropped() != 0 {
		t.Errorf("OutboxDropped = %d after a rollback, want 0", s.OutboxDropped())
	}
	if got := pendingIDs(t, s); got != "[first]" {
		t.Errorf("outbox = %s, want the rolled-back state [first]", got)
	}
}

const (
	frozenV1SHA256           = "76786449c96044d7d7d18c7b8acc6c8d485552a83df3bf84d0536d12be5aceae"
	frozenBeforeRenameSHA256 = "388a9186b4b2076eea06611a42a386327b770416685664550f208f1575bfb58a"
)
