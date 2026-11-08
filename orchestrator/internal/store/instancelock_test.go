// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// A second controller on one database is refused while the first holds the lock and accepted
// once it is released; another database is independent; a symbolic link at the lock's path is
// refused.
func TestLockInstance(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "orch.db")
	lock, err := LockInstance(db)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(db + ".lock"); string(b) != strconv.Itoa(os.Getpid()) {
		t.Errorf("lock file holds %q, want this pid", b)
	}
	if _, err := LockInstance(db); !errors.Is(err, ErrInstanceLocked) {
		t.Fatalf("second LockInstance = %v, want ErrInstanceLocked", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("a second Release = %v, want nothing", err)
	}
	again, err := LockInstance(db)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	again.Release()
	other, err := LockInstance(filepath.Join(dir, "other.db"))
	if err != nil {
		t.Fatal(err)
	}
	other.Release()

	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "linked.db")
	if err := os.Symlink(target, linked+".lock"); err != nil {
		t.Fatal(err)
	}
	if l, err := LockInstance(linked); err == nil {
		l.Release()
		t.Fatal("a symbolic link at the lock's path was followed")
	}
}
