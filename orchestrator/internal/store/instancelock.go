// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

// ErrInstanceLocked: another controller already holds the database's instance lock.
var ErrInstanceLocked = errors.New("another controller instance holds this database's lock")

// InstanceLock is a held instance lock (LockInstance): holding one is what proves a caller holds
// the database's lock, where a flag only claims it. Release gives it up; it is idempotent.
type InstanceLock struct {
	mu   sync.Mutex
	f    *os.File // nil once released
	path string   // the lock file's path, from the database's resolved path
}

// LockInstance takes an exclusive, non-blocking flock(2) on <dbPath>.lock for the life of the
// process, so two controllers never share one database. A second controller would be destructive,
// not merely redundant: its startup ReconcileOrphans fails the first one's running jobs, both
// schedulers admit from one queue against separate in-memory capacity, and a cancel reaching the
// wrong process finds no executor. OpenWith takes it, or is given it (Options.Lock).
//
// The lock's path derives from the database's resolved path (symbolic links in the directory, and
// a link at the database itself, followed), so two spellings of one database share one lock. The
// lock is released by Release, or by the process exiting, since the kernel drops it with the
// descriptor, which O_CLOEXEC keeps out of runner subprocesses (one that outlived a crashed
// controller would otherwise go on holding it). O_NOFOLLOW refuses a symbolic link planted at the
// lock's path. The holder's pid is written into the file, for diagnosis only. flock is only as
// good as the filesystem: the database belongs on a local one, never a network share, where two
// hosts' locks need not see each other.
func LockInstance(dbPath string) (*InstanceLock, error) {
	resolved, err := resolveDBPath(dbPath)
	if err != nil {
		return nil, fmt.Errorf("instance lock: %w", err)
	}
	path := resolved + ".lock"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("instance lock %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		holder, _ := os.ReadFile(path)
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s (holder pid %q)", ErrInstanceLocked, path, string(holder))
		}
		return nil, fmt.Errorf("instance lock %s: %w", path, err)
	}
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0)
	}
	return &InstanceLock{f: f, path: path}, nil
}

// Release gives the lock up. Releasing a released (or nil) lock does nothing.
func (l *InstanceLock) Release() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// heldFor reports whether l is still held and is the lock of the database at dbPath.
func (l *InstanceLock) heldFor(dbPath string) error {
	if l == nil {
		return errors.New("store: no instance lock was given")
	}
	resolved, err := resolveDBPath(dbPath)
	if err != nil {
		return fmt.Errorf("instance lock: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case l.f == nil:
		return errors.New("store: the instance lock given was released")
	case l.path != resolved+".lock":
		return fmt.Errorf("store: the instance lock given is %s, not this database's", l.path)
	}
	return nil
}

// resolveDBPath is dbPath absolute, with every symbolic link in its directory, and one at the
// file itself, resolved. The file need not exist.
func resolveDBPath(dbPath string) (string, error) {
	abs, err := filepath.Abs(dbPath)
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r, nil
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(abs)), nil
}
