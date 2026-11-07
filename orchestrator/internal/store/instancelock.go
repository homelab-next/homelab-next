// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// ErrInstanceLocked: another controller already holds the database's instance lock.
var ErrInstanceLocked = errors.New("another controller instance holds this database's lock")

// LockInstance takes an exclusive, non-blocking flock(2) on <dbPath>.lock for the life of the
// process, so two controllers never share one database. A second controller would be destructive,
// not merely redundant: its startup ReconcileOrphans fails the first one's running jobs, both
// schedulers admit from one queue against separate in-memory capacity, and a cancel reaching the
// wrong process finds no executor. OpenWith takes it (or checks the caller holds it).
//
// The lock's path derives from the database's resolved path (symbolic links in the directory, and
// a link at the database itself, followed), so two spellings of one database share one lock. The
// returned func releases it; so does the process exiting, since the kernel drops it with the
// descriptor, which O_CLOEXEC keeps out of runner subprocesses (one that outlived a crashed
// controller would otherwise go on holding it). O_NOFOLLOW refuses a symbolic link planted at the
// lock's path. The holder's pid is written into the file, for diagnosis only. flock is only as
// good as the filesystem: the database belongs on a local one, never a network share, where two
// hosts' locks need not see each other.
func LockInstance(dbPath string) (release func() error, err error) {
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
	return f.Close, nil
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
