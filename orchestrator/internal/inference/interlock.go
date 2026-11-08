// SPDX-License-Identifier: Apache-2.0

// Package inference holds what the controller shares with every other caller of a local
// inference backend: the cross-process interlock that serialises calls to a backend that can
// serve only one at a time, and the gateway tag a job's model requests carry. The controller
// sends no model request itself (a runner session does, through the gateway), so there is no
// client here.
package inference

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultPollInterval is how often Acquire retries the lock while it waits.
const DefaultPollInterval = 500 * time.Millisecond

// ErrWaitEnded is what Acquire returns, wrapping ctx's error, when ctx ended before the lock was
// free. Which of the caller's deadlines that was (its own bound on the wait, or the job's) is the
// caller's to tell: the pool treats an expired wait bound as the backend being busy
// (runner.BackendFault) and a cancelled job as a cancel.
var ErrWaitEnded = errors.New("interlock: wait ended before the lock was free")

// Interlock is an exclusive flock(2) on one shared lock file. Every caller of the backend it
// guards takes the same file, whatever program it is (a shell script with flock(1) included), so
// calls from separate processes never overlap on a backend that serves one call at a time.
//
// Each Acquire opens its own descriptor and polls the lock without blocking: no Go-level mutex
// is held across a wait, so a goroutine waiting for the lock can never stop another goroutine
// from releasing it, and any number of goroutines may share one *Interlock.
//
// A nil *Interlock is disabled (NewInterlock("")): Acquire returns at once with a Held whose
// Release does nothing, for a backend that serves calls concurrently.
type Interlock struct {
	path string
	poll time.Duration
}

// NewInterlock returns the interlock on the lock file at path, or nil (disabled) when path is "".
// The path must be clean and absolute (Acquire refuses any other): a relative one would depend on
// the working directory, and every caller must name the same file. Put it in a directory only the
// service and its cooperating callers can write, such as the unit's RuntimeDirectory
// (/run/<service>/). pollInterval <= 0 is DefaultPollInterval.
func NewInterlock(path string, pollInterval time.Duration) *Interlock {
	if path == "" {
		return nil
	}
	if pollInterval <= 0 {
		pollInterval = DefaultPollInterval
	}
	return &Interlock{path: path, poll: pollInterval}
}

// Held is one acquired lock. Release it once; releasing again does nothing.
type Held struct {
	file *os.File
}

// Acquire takes the lock, waiting while another process or descriptor holds it, until ctx ends
// (ErrWaitEnded, wrapping ctx.Err(), naming the holder's pid when the kernel reports it). A ctx
// with no deadline waits without bound.
//
// The lock file is opened read-only, as flock(1) opens it, so a lock file a cooperating caller
// created serves too, and is created owner-only (0600) if it does not exist; a site whose
// callers run as other users creates it beforehand, group-readable for a group they share. A
// lock file in a directory anyone may write is refused (anyone could replace it, and two callers
// holding two files exclude nothing), and so is a symbolic link or anything but a regular file at
// its path, so the open can neither be redirected nor hang on a FIFO. The descriptor is
// close-on-exec, so no runner subprocess inherits the lock.
func (l *Interlock) Acquire(ctx context.Context) (*Held, error) {
	if l == nil {
		return &Held{}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWaitEnded, err)
	}
	if !filepath.IsAbs(l.path) || filepath.Clean(l.path) != l.path {
		return nil, fmt.Errorf("interlock: lock path %q is not a clean absolute path", l.path)
	}
	if di, err := os.Stat(filepath.Dir(l.path)); err != nil {
		return nil, fmt.Errorf("interlock: the lock file's directory: %w", err)
	} else if di.Mode().Perm()&0o002 != 0 {
		return nil, fmt.Errorf("interlock: the lock file's directory %s is writable by anyone", filepath.Dir(l.path))
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, fmt.Errorf("interlock: open the lock file: %w", err)
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		if err == nil {
			err = errors.New("not a regular file")
		}
		return nil, fmt.Errorf("interlock: the lock file: %w", err)
	}
	ticker := time.NewTicker(l.poll)
	defer ticker.Stop()
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return &Held{file: f}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			f.Close()
			return nil, fmt.Errorf("interlock: flock: %w", err)
		}
		select {
		case <-ctx.Done():
			holder := holderOf(f)
			f.Close()
			if holder != "" {
				return nil, fmt.Errorf("%w (held by pid %s): %w", ErrWaitEnded, holder, ctx.Err())
			}
			return nil, fmt.Errorf("%w: %w", ErrWaitEnded, ctx.Err())
		case <-ticker.C:
		}
	}
}

// holderOf returns the pid /proc/locks names as holding a flock on f's inode, or "" when it names
// none or cannot be read (another pid namespace, no /proc). It is for the error message only: a
// pid can be reused and the lock can change hands at any moment.
func holderOf(f *os.File) string {
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	data, err := os.ReadFile("/proc/locks")
	if err != nil {
		return ""
	}
	want := fmt.Sprintf("%02x:%02x:%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)), st.Ino)
	for _, line := range strings.Split(string(data), "\n") {
		// "1: FLOCK  ADVISORY  WRITE 4242 08:01:131 0 EOF"; a waiter's line has "->" after the
		// number, and a non-blocking attempt never waits
		fields := strings.Fields(line)
		if len(fields) >= 6 && fields[1] == "FLOCK" && fields[5] == want {
			return fields[4]
		}
	}
	return ""
}

// Release unlocks and closes the lock. A nil, disabled or already released Held does nothing.
func (h *Held) Release() error {
	if h == nil || h.file == nil {
		return nil
	}
	unlockErr := unix.Flock(int(h.file.Fd()), unix.LOCK_UN)
	closeErr := h.file.Close()
	h.file = nil
	if unlockErr != nil {
		return fmt.Errorf("interlock: unlock: %w", unlockErr)
	}
	return closeErr
}
