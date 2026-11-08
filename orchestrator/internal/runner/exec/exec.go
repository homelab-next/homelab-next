// SPDX-License-Identifier: Apache-2.0

// Package exec is a generic subprocess runner (runner.Runner): each session is one process started
// from an argv template, with no shell. Its stdout is the session's answer, its exit status the
// session's outcome, and a cancel or the attempt's ceiling ends its whole process group.
//
// It is not any agent harness: it knows no home layout, no turn counter and no progress signal.
// What it enforces of runner.Limits is the attempt's Timeout; a stall timeout, a turn cap and a
// liveness mode are the program's own to honour (New refuses none of them, since the pool sets the
// same limits for every runner). It is what the in-repository conformance job and the controller's
// process tests drive; an agent harness is a provider module's runner (ADR-0026 stage 3).
package exec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
)

// Defaults of Config's bounds.
const (
	DefaultMaxResponseBytes = 1 << 20
	DefaultMaxStderrBytes   = 64 << 10
	DefaultKillGrace        = 5 * time.Second
	// maxUsageBytes bounds the usage report read back.
	maxUsageBytes = 1 << 20
	// maxErrorStderr bounds the stderr excerpt a failure's error text carries.
	maxErrorStderr = 2 << 10
)

// The placeholders an argv element may hold; each is replaced by the session's value, inside the
// element, never split into more elements.
const (
	PromptPlaceholder    = "{prompt}"
	UsagePathPlaceholder = "{usage_path}"
	ToolsetsPlaceholder  = "{toolsets}"
	RunIDPlaceholder     = "{run_id}"
	AgentKeyPlaceholder  = "{agent_key}"
	LanePlaceholder      = "{lane}"
	HomePlaceholder      = "{home}"
	BackendPlaceholder   = "{backend}"
)

var placeholders = []string{PromptPlaceholder, UsagePathPlaceholder, ToolsetsPlaceholder, RunIDPlaceholder,
	AgentKeyPlaceholder, LanePlaceholder, HomePlaceholder, BackendPlaceholder}

// Config is the runner's command and bounds.
type Config struct {
	// Argv is the command: an absolute program path or a name found on PATH, then its arguments,
	// with placeholders. Without {prompt} in any element the prompt goes to the process's stdin.
	Argv []string
	// UsageArgs are appended when the session asks for a usage report (Session.UsagePath set),
	// ToolsetsArgs when it has toolsets: say ["--usage-file", "{usage_path}"] and
	// ["--toolsets", "{toolsets}"]. Neither is passed otherwise.
	UsageArgs    []string
	ToolsetsArgs []string
	// ExitClasses classes a non-zero exit status; an unlisted one is runner.TurnFailed. A program
	// that reports the gateway's concurrency_limited refusal says so by its own exit status,
	// mapped here to runner.ConcurrencyLimited.
	ExitClasses map[int]runner.Class
	// EnvAllowlist: the process gets only these of the controller's environment variables (an
	// exact name, or a prefix ending in "*"), then the session's HNX_* variables. Empty: none of
	// them (fail-closed: a session never inherits what nobody listed).
	EnvAllowlist []string
	// DenyEnv are variables a session never gets, whatever EnvAllowlist says: the names the
	// controller reads its own secrets from (the event forwarder's token, say). A session's
	// output is the answer a caller reads, so a variable it can print is one a caller can read.
	DenyEnv []string
	// RunDirBase is where each session gets a fresh owner-only working directory, removed when it
	// ends; empty is the system's temporary directory.
	RunDirBase string
	// MaxResponseBytes bounds stdout (more fails the session), MaxStderrBytes the stderr kept;
	// KillGrace is how long a cancelled group has between SIGTERM and SIGKILL. 0 is the default.
	MaxResponseBytes int64
	MaxStderrBytes   int64
	KillGrace        time.Duration
}

// Runner is the subprocess runner.
type Runner struct{ cfg Config }

var _ runner.Runner = (*Runner)(nil)

// New checks cfg and returns its runner.
func New(cfg Config) (*Runner, error) {
	if len(cfg.Argv) == 0 || cfg.Argv[0] == "" {
		return nil, errors.New("exec runner: argv is empty")
	}
	if strings.Contains(cfg.Argv[0], "{") {
		return nil, errors.New("exec runner: the program (argv[0]) may hold no placeholder")
	}
	for _, list := range [][]string{cfg.Argv, cfg.UsageArgs, cfg.ToolsetsArgs} {
		for _, a := range list {
			if strings.ContainsRune(a, 0) {
				return nil, errors.New("exec runner: an argument holds a NUL byte")
			}
		}
	}
	for code, c := range cfg.ExitClasses {
		if code <= 0 || code > 255 {
			return nil, fmt.Errorf("exec runner: exit_classes has exit status %d, not 1 to 255", code)
		}
		if c == runner.Internal || c == runner.KilledByController || c == runner.KilledExternally {
			return nil, fmt.Errorf("exec runner: exit status %d cannot be classed %s", code, c)
		}
	}
	for _, e := range cfg.EnvAllowlist {
		if e == "" || e == "*" || strings.ContainsAny(e, "=\x00") || strings.Contains(strings.TrimSuffix(e, "*"), "*") {
			return nil, fmt.Errorf("exec runner: env_allowlist entry %q is not a name or a name prefix ending in *", e)
		}
	}
	if cfg.RunDirBase != "" && !filepath.IsAbs(cfg.RunDirBase) {
		return nil, errors.New("exec runner: run_dir_base must be absolute")
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if cfg.MaxStderrBytes <= 0 {
		cfg.MaxStderrBytes = DefaultMaxStderrBytes
	}
	if cfg.KillGrace <= 0 {
		cfg.KillGrace = DefaultKillGrace
	}
	return &Runner{cfg: cfg}, nil
}

// Run implements runner.Runner. It never returns a nil *Result. Classes: the caller's context
// ending is runner.KilledByController, the session's Timeout runner.TimeoutCeiling, a signal not
// sent by the runner runner.KilledExternally, a non-zero exit its ExitClasses entry or
// runner.TurnFailed, and an answer over MaxResponseBytes runner.TurnFailed.
func (r *Runner) Run(ctx context.Context, s runner.Session) (*runner.Result, error) {
	res := &runner.Result{}
	if err := ctx.Err(); err != nil {
		return res, runner.Wrap(runner.KilledByController, fmt.Errorf("exec runner: not started: %w", err))
	}
	dir, err := os.MkdirTemp(r.cfg.RunDirBase, "run-")
	if err != nil {
		return res, fmt.Errorf("exec runner: make the run directory: %w", err)
	}
	defer os.RemoveAll(dir)
	env := r.environ(s)
	if s.Servers != nil {
		path := filepath.Join(dir, "servers.json")
		data, err := json.Marshal(s.Servers)
		if err == nil {
			err = os.WriteFile(path, data, 0o600)
		}
		if err != nil {
			return res, fmt.Errorf("exec runner: write the servers file: %w", err)
		}
		env = append(env, "HNX_SERVERS_FILE="+path)
	}

	runCtx := ctx
	if s.Limits.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, s.Limits.Timeout)
		defer cancel()
	}
	argv, stdinPrompt := r.argv(s)
	cmd := osexec.CommandContext(runCtx, argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if stdinPrompt {
		cmd.Stdin = strings.NewReader(s.Prompt)
	}
	stdout := &capped{max: r.cfg.MaxResponseBytes}
	stderr := &capped{max: r.cfg.MaxStderrBytes}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// A cancel or the ceiling ends the whole group: SIGTERM first, SIGKILL after KillGrace (the
	// os/exec WaitDelay kills the leader and stops waiting on pipes a descendant holds open).
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = r.cfg.KillGrace
	if err := cmd.Start(); err != nil {
		return res, fmt.Errorf("exec runner: start %s: %w", filepath.Base(argv[0]), err)
	}
	pgid := cmd.Process.Pid
	// Whatever is left of the group (a descendant that outlived the leader) goes with it. The
	// group is killed while its leader is exited but not yet reaped, so the group id cannot have
	// been reused by an unrelated group; then the leader is reaped, and Run waits, at most
	// KillGrace, until no member of the group is still running (one stuck in an uninterruptible
	// wait cannot hold Run for ever).
	waitExited(pgid)
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	waitErr := cmd.Wait()
	sweepGroup(pgid, r.cfg.KillGrace)

	res.Stderr = stderr.String()
	res.ExitCode = cmd.ProcessState.ExitCode()
	if s.UsagePath != "" {
		if u, err := readUsage(s.UsagePath); err == nil && u != nil {
			res.Usage = u
			if id, ok := u["session_id"].(string); ok {
				res.SessionID = id
			}
		}
	}
	switch {
	case ctx.Err() != nil:
		return res, runner.Wrap(runner.KilledByController, fmt.Errorf("exec runner: stopped by the controller: %w", ctx.Err()))
	case runCtx.Err() != nil:
		return res, runner.Wrap(runner.TimeoutCeiling, fmt.Errorf("exec runner: the attempt's ceiling (%s) ended the session", s.Limits.Timeout))
	}
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return res, runner.Wrap(runner.KilledExternally, fmt.Errorf("exec runner: ended by %s", ws.Signal()))
	}
	if waitErr != nil && res.ExitCode == 0 {
		// The program exited 0, but a descendant outside its group (one that called setsid) held
		// its output open past KillGrace: the answer read may be cut short, so it is no answer.
		return res, runner.Wrap(runner.TurnFailed, fmt.Errorf("exec runner: the program exited, but its output stayed open past the kill grace: %w", waitErr))
	}
	if res.ExitCode != 0 {
		c, ok := r.cfg.ExitClasses[res.ExitCode]
		if !ok {
			c = runner.TurnFailed
		}
		return res, runner.Wrap(c, fmt.Errorf("exec runner: exit status %d: %s", res.ExitCode, tail(res.Stderr, maxErrorStderr)))
	}
	if stdout.over {
		return res, runner.Wrap(runner.TurnFailed, fmt.Errorf("exec runner: the answer is larger than %d bytes", r.cfg.MaxResponseBytes))
	}
	res.Response = stdout.String()
	return res, nil
}

// waitExited blocks until process pid has exited, leaving it unreaped (WNOWAIT): os/exec's Wait
// reaps it after.
func waitExited(pid int) {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if err != unix.EINTR {
			return
		}
	}
}

// sweepGroup waits until no member of process group pgid is running (a zombie is not), polling
// /proc, for at most bound. It reports whether the group is gone.
func sweepGroup(pgid int, bound time.Duration) bool {
	deadline := time.Now().Add(bound)
	for {
		if !groupRunning(pgid) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// groupRunning reports whether any process of group pgid is still running (not a zombie).
func groupRunning(pgid int) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name()[0] < '0' || e.Name()[0] > '9' {
			continue
		}
		data, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		st := string(data)
		i := strings.LastIndexByte(st, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(st[i+1:]) // state, ppid, pgrp, ...
		if len(f) < 3 || f[0] == "Z" || f[0] == "X" {
			continue
		}
		if f[2] == strconv.Itoa(pgid) {
			return true
		}
	}
	return false
}

// argv is the session's command line, and whether the prompt goes to stdin (no element holds it).
func (r *Runner) argv(s runner.Session) ([]string, bool) {
	values := map[string]string{
		PromptPlaceholder: s.Prompt, UsagePathPlaceholder: s.UsagePath, ToolsetsPlaceholder: runner.JoinToolsets(s.Toolsets),
		RunIDPlaceholder: s.RunID, AgentKeyPlaceholder: s.AgentKey, LanePlaceholder: s.Lane,
		HomePlaceholder: s.Target.Home, BackendPlaceholder: s.Target.Backend,
	}
	args := append([]string(nil), r.cfg.Argv...)
	if s.UsagePath != "" {
		args = append(args, r.cfg.UsageArgs...)
	}
	if len(s.Toolsets) > 0 {
		args = append(args, r.cfg.ToolsetsArgs...)
	}
	stdin := true
	for i, a := range args {
		if strings.Contains(a, PromptPlaceholder) {
			stdin = false
		}
		args[i] = expand(a, values)
	}
	return args, stdin
}

// expand replaces each placeholder in a in one left-to-right pass, so a value holding a
// placeholder's text is never expanded again.
func expand(a string, values map[string]string) string {
	var b strings.Builder
	for len(a) > 0 {
		i := strings.IndexByte(a, '{')
		if i < 0 {
			b.WriteString(a)
			break
		}
		b.WriteString(a[:i])
		a = a[i:]
		matched := false
		for _, p := range placeholders {
			if strings.HasPrefix(a, p) {
				b.WriteString(values[p])
				a = a[len(p):]
				matched = true
				break
			}
		}
		if !matched {
			b.WriteByte('{')
			a = a[1:]
		}
	}
	return b.String()
}

// environ is the process's environment: the allowed part of the controller's, then the session's
// own variables (which win over an inherited one of the same name).
func (r *Runner) environ(s runner.Session) []string {
	own := map[string]string{
		"HNX_RUN_ID": s.RunID, "HNX_AGENT_KEY": s.AgentKey, "HNX_LANE": s.Lane, "HNX_GATEWAY_TAG": s.GatewayTag,
		"HNX_USAGE_PATH": s.UsagePath, "HNX_HOME": s.Target.Home, "HNX_BACKEND": s.Target.Backend,
		"HNX_TOOLSETS": runner.JoinToolsets(s.Toolsets),
	}
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if _, mine := own[name]; mine || name == "HNX_SERVERS_FILE" || slices.Contains(r.cfg.DenyEnv, name) {
			continue
		}
		if r.allowed(name) {
			env = append(env, kv)
		}
	}
	for _, k := range []string{"HNX_RUN_ID", "HNX_AGENT_KEY", "HNX_LANE", "HNX_GATEWAY_TAG", "HNX_USAGE_PATH", "HNX_HOME", "HNX_BACKEND", "HNX_TOOLSETS"} {
		env = append(env, k+"="+own[k])
	}
	return env
}

func (r *Runner) allowed(name string) bool {
	_, ok := Covers(r.cfg.EnvAllowlist, name)
	return ok
}

// Covers reports whether an allowlist entry (an exact name, or a prefix ending in "*") lets name
// through, and which; an empty list lets nothing through.
func Covers(allowlist []string, name string) (string, bool) {
	for _, e := range allowlist {
		if p, ok := strings.CutSuffix(e, "*"); ok {
			if strings.HasPrefix(name, p) {
				return e, true
			}
		} else if name == e {
			return e, true
		}
	}
	return "", false
}

// readUsage reads the session's usage report: a regular file, not a link, at most maxUsageBytes, a
// JSON object. A missing file is no report (nil, nil).
func readUsage(path string) (map[string]any, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, errors.New("the usage report is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxUsageBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxUsageBytes {
		return nil, errors.New("the usage report is too large")
	}
	var u map[string]any
	if err := json.Unmarshal(data, &u); err != nil {
		return nil, err
	}
	return u, nil
}

// capped keeps the first max bytes written to it and notes whether more came.
type capped struct {
	buf  bytes.Buffer
	max  int64
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	room := c.max - int64(c.buf.Len())
	if int64(len(p)) > room {
		if room > 0 {
			c.buf.Write(p[:room])
		}
		c.over = true
		return len(p), nil
	}
	c.buf.Write(p)
	return len(p), nil
}

func (c *capped) String() string { return c.buf.String() }

// tail is the last max bytes of s, cut at a line start when one is near.
func tail(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	s = s[len(s)-max:]
	if i := strings.IndexByte(s, '\n'); i >= 0 && i < len(s)/2 {
		s = s[i+1:]
	}
	return "..." + s
}
