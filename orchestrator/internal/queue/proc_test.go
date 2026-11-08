// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
)

// procRunner is a subprocess runner for the tests that need a real process to die: a cancel, a
// deadline, a signal the controller did not send. Each session runs this test binary again (the
// helper, below) in its own process group, which spawns a child of its own, so a session is a
// process tree. Cancelling the session's context kills the whole group before Run returns, as the
// runner seam requires; an exit by a signal it did not send is runner.KilledExternally, any other
// failed exit runner.TurnFailed, and stdout is the answer.
type procRunner struct {
	mode string // the helper's behaviour: answer, fail or hang
	dir  string // the helper writes its own and its child's pid here, one file per session
}

const helperEnv = "QUEUE_TEST_HELPER"

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		os.Exit(helperMain(mode))
	}
	os.Exit(m.Run())
}

// helperMain is the session body. "hang" and "answer" start a child that sleeps (the tree), write
// "<pid> <child pid>" to the pid file, then hang until killed, or answer.
func helperMain(mode string) int {
	if mode == "child" {
		time.Sleep(time.Hour)
		return 0
	}
	child := exec.Command(os.Args[0])
	child.Env = append(os.Environ(), helperEnv+"=child")
	if err := child.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	pids := fmt.Sprintf("%d %d", os.Getpid(), child.Process.Pid)
	if err := os.WriteFile(os.Getenv("QUEUE_TEST_PIDFILE")+".tmp", []byte(pids), 0o600); err != nil {
		return 3
	}
	if err := os.Rename(os.Getenv("QUEUE_TEST_PIDFILE")+".tmp", os.Getenv("QUEUE_TEST_PIDFILE")); err != nil {
		return 3
	}
	switch mode {
	case "answer":
		_ = child.Process.Kill()
		_ = child.Wait()
		fmt.Print("finding filed")
		return 0
	case "fail":
		_ = child.Process.Kill()
		_ = child.Wait()
		fmt.Fprint(os.Stderr, "the turn failed")
		return 1
	}
	time.Sleep(time.Hour)
	return 0
}

func (p *procRunner) Run(ctx context.Context, s runner.Session) (*runner.Result, error) {
	pidFile := filepath.Join(p.dir, s.RunID+"."+strconv.FormatInt(time.Now().UnixNano(), 10)+".pids")
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), helperEnv+"="+p.mode, "QUEUE_TEST_PIDFILE="+pidFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Start(); err != nil {
		return &runner.Result{}, runner.Wrap(runner.Internal, err)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	var werr error
	killed := false
	select {
	case werr = <-waited:
	case <-ctx.Done():
		killed = true
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		werr = <-waited
	}
	// The group is gone before Run returns, the child included, however the session ended.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	res := &runner.Result{Response: out.String(), Stderr: errOut.String(), ExitCode: cmd.ProcessState.ExitCode(),
		Usage: map[string]any{"input_tokens": float64(10), "output_tokens": float64(2)}}
	var ee *exec.ExitError
	switch {
	case killed:
		return res, runner.Wrap(runner.KilledByController, fmt.Errorf("session killed: %w", ctx.Err()))
	case errors.As(werr, &ee) && ee.Sys().(syscall.WaitStatus).Signaled():
		return res, runner.Wrap(runner.KilledExternally, werr)
	case werr != nil:
		return res, runner.Wrap(runner.TurnFailed, werr)
	}
	return res, nil
}

// sessionPids waits for the n-th (0-based) session's pid file, by its order of creation, and
// returns the session's and its child's pids.
func (p *procRunner) sessionPids(t *testing.T, runID string, n int) (pid, child int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		files, _ := filepath.Glob(filepath.Join(p.dir, runID+".*.pids"))
		if len(files) > n {
			sortByStamp(files)
			b, err := os.ReadFile(files[n])
			if err == nil {
				f := strings.Fields(string(b))
				a, _ := strconv.Atoi(f[0])
				c, _ := strconv.Atoi(f[1])
				return a, c
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("session %d of %s never started", n, runID)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// sortByStamp orders pid files by the creation stamp in their names.
func sortByStamp(files []string) {
	stamp := func(f string) int64 {
		parts := strings.Split(filepath.Base(f), ".")
		n, _ := strconv.ParseInt(parts[len(parts)-2], 10, 64)
		return n
	}
	for i := 1; i < len(files); i++ {
		for j := i; j > 0 && stamp(files[j]) < stamp(files[j-1]); j-- {
			files[j], files[j-1] = files[j-1], files[j]
		}
	}
}

// gone reports whether pid no longer runs: no such process, or a zombie waiting for its reaper.
func gone(pid int) bool {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return true
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true
	}
	// The state follows the command, which is in parentheses.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	return i >= 0 && i+2 < len(s) && (s[i+2] == 'Z' || s[i+2] == 'X')
}

func waitGone(t *testing.T, pids ...int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for _, pid := range pids {
		for !gone(pid) {
			if time.Now().After(deadline) {
				t.Fatalf("process %d still runs", pid)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// killProcess sends SIGKILL to pid alone: a signal the controller did not send.
func killProcess(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) }
