// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const fastPoll = 5 * time.Millisecond

func lockPath(t *testing.T) string { return filepath.Join(t.TempDir(), "backend.lock") }

func TestInterlock_EmptyPathDisables(t *testing.T) {
	l := NewInterlock("", fastPoll)
	if l != nil {
		t.Fatalf("NewInterlock(\"\") = %v, want nil", l)
	}
	// a disabled interlock never serialises: two holders at once, both immediately
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a, err := l.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.Acquire(ctx)
	if err != nil || a == nil || b == nil {
		t.Fatalf("second acquire on a disabled interlock: %v", err)
	}
	for _, h := range []*Held{a, a, b, nil} {
		if err := h.Release(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInterlock_AcquireReleaseThenAcquireAgain(t *testing.T) {
	l := NewInterlock(lockPath(t), fastPoll)
	h, err := l.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Release(); err != nil {
		t.Fatal(err)
	}
	if err := h.Release(); err != nil {
		t.Fatalf("a second release: %v", err)
	}
	h, err = l.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h.Release()
}

// The wait is bounded by ctx: against a lock held the whole time, Acquire returns ErrWaitEnded
// wrapping ctx's error, promptly; with ctx already done it does not try at all.
func TestInterlock_WaitEndsWithTheContext(t *testing.T) {
	path := lockPath(t)
	held, err := NewInterlock(path, fastPoll).Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = NewInterlock(path, fastPoll).Acquire(ctx)
	if !errors.Is(err, ErrWaitEnded) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want ErrWaitEnded wrapping DeadlineExceeded", err)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("the wait took %v against a 100ms bound", el)
	}

	done, cancelDone := context.WithCancel(context.Background())
	cancelDone()
	if _, err := NewInterlock(lockPath(t), fastPoll).Acquire(done); !errors.Is(err, ErrWaitEnded) || !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled ctx: %v", err)
	}
}

func TestInterlock_SecondHolderWaitsForTheFirst(t *testing.T) {
	path := lockPath(t)
	first, err := NewInterlock(path, fastPoll).Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan *Held, 1)
	go func() {
		h, err := NewInterlock(path, fastPoll).Acquire(context.Background())
		if err != nil {
			t.Error(err)
		}
		got <- h
	}()
	select {
	case <-got:
		t.Fatal("the second holder got the lock while the first held it")
	case <-time.After(100 * time.Millisecond):
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	select {
	case h := <-got:
		h.Release()
	case <-time.After(10 * time.Second):
		t.Fatal("the second holder never got the released lock")
	}
}

// Many goroutines sharing one *Interlock take turns and never deadlock: no mutex is held across
// a wait, so a waiting goroutine cannot stop a holder's Release.
func TestInterlock_SharedByGoroutinesIsMutuallyExclusive(t *testing.T) {
	l := NewInterlock(lockPath(t), time.Millisecond)
	var (
		mu      sync.Mutex
		inside  int
		overlap bool
		wg      sync.WaitGroup
	)
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				h, err := l.Acquire(context.Background())
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				inside++
				overlap = overlap || inside > 1
				mu.Unlock()
				time.Sleep(time.Millisecond)
				mu.Lock()
				inside--
				mu.Unlock()
				if err := h.Release(); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("goroutines sharing one interlock did not finish: deadlocked")
	}
	if overlap {
		t.Fatal("two goroutines held the lock at once")
	}
}

// A symbolic link at the lock path is refused (the open could be redirected), and so is a FIFO,
// without hanging the open.
func TestInterlock_RefusesALinkOrAFIFO(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	link := filepath.Join(dir, "link.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewInterlock(link, fastPoll).Acquire(context.Background()); err == nil {
		t.Fatal("a symlinked lock file was accepted")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the open created the link's target")
	}
	fifo := filepath.Join(dir, "fifo.lock")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := NewInterlock(fifo, fastPoll).Acquire(context.Background()); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was accepted as the lock file")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the open hung on a FIFO")
	}
}

// helperEnv names the lock file a re-executed test binary holds (TestInterlockHelperProcess).
const helperEnv = "ORCHESTRATOR_INTERLOCK_HELPER_LOCK"

// TestInterlockHelperProcess is not a test of its own: re-executed by holdInAnotherProcess, it
// takes the lock in a separate process, says so on stdout, and releases it when stdin closes.
func TestInterlockHelperProcess(t *testing.T) {
	path := os.Getenv(helperEnv)
	if path == "" {
		return
	}
	h, err := NewInterlock(path, fastPoll).Acquire(context.Background())
	if err != nil {
		os.Stdout.WriteString("error " + err.Error() + "\n")
		os.Exit(3)
	}
	os.Stdout.WriteString("held\n")
	io.Copy(io.Discard, os.Stdin)
	h.Release()
	os.Exit(0)
}

// holdInAnotherProcess starts this test binary again as a process holding the lock at path, and
// returns once it holds it; the returned func makes it release and waits for it to exit.
func holdInAnotherProcess(t *testing.T, path string) (release func(), pid int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestInterlockHelperProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(), helperEnv+"="+path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(stdout).ReadString('\n')
		line <- s
		io.Copy(io.Discard, stdout)
	}()
	select {
	case s := <-line:
		if s != "held\n" {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatalf("the helper process said %q", s)
		}
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatal("the helper process never took the lock")
	}
	return func() {
		stdin.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("the helper process: %v", err)
		}
	}, cmd.Process.Pid
}

// The lock holds across processes: while another process holds it, Acquire here waits (and its
// bound ends the wait); once that process lets go, Acquire here gets it.
func TestInterlock_ExcludesAnotherProcess(t *testing.T) {
	path := lockPath(t)
	release, pid := holdInAnotherProcess(t, path)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_, err := NewInterlock(path, fastPoll).Acquire(ctx)
	cancel()
	if !errors.Is(err, ErrWaitEnded) {
		release()
		t.Fatalf("acquired a lock another process holds: %v", err)
	}
	// the holder is named when the kernel reports it (/proc/locks, same pid namespace)
	if _, perr := os.Stat("/proc/locks"); perr == nil && !strings.Contains(err.Error(), "held by pid "+strconv.Itoa(pid)) {
		release()
		t.Fatalf("the expired wait does not name the holder %d: %v", pid, err)
	}
	release()
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	h, err := NewInterlock(path, fastPoll).Acquire(ctx)
	if err != nil {
		t.Fatalf("after the other process let go: %v", err)
	}
	h.Release()
}

// The interlock is the lock flock(1) takes, so a shell caller and the controller exclude each
// other on one lock file.
func TestInterlock_ExcludesFlockCommand(t *testing.T) {
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("flock(1) not installed")
	}
	path := lockPath(t)
	h, err := NewInterlock(path, fastPoll).Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("flock", "-n", path, "true").Run(); err == nil {
		t.Fatal("flock -n took the lock while the interlock held it")
	}
	if err := h.Release(); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("flock", "-n", path, "true").Run(); err != nil {
		t.Fatalf("flock -n after release: %v", err)
	}
}

// The lock path must be clean and absolute; a new lock file is owner-only; a lock file in a
// directory anyone may write is refused.
func TestInterlock_PathModeAndDirectory(t *testing.T) {
	for _, bad := range []string{"backend.lock", "./backend.lock", "/run/x/../backend.lock", "/run/x/"} {
		if h, err := NewInterlock(bad, fastPoll).Acquire(context.Background()); err == nil || !strings.Contains(err.Error(), "clean absolute") {
			h.Release()
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
	path := lockPath(t)
	h, err := NewInterlock(path, fastPoll).Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h.Release()
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("a new lock file's mode: %v, %v", fi.Mode(), err)
	}
	open := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o1777); err != nil {
		t.Fatal(err)
	}
	if _, err := NewInterlock(filepath.Join(open, "backend.lock"), fastPoll).Acquire(context.Background()); err == nil || !strings.Contains(err.Error(), "writable by anyone") {
		t.Fatalf("a world-writable directory: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(open, "backend.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the lock file was created in a world-writable directory")
	}
}
