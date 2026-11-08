// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
)

// The sessions in these tests are this test binary re-executed as a helper (TestHelperProcess):
// argv after "--" names what it does. No test decides by elapsed time; the one that waits for a
// helper to start polls for the file it writes.

func helperArgv(mode string, args ...string) []string {
	return append([]string{os.Args[0], "-test.run=^TestHelperProcess$", "--", mode}, args...)
}

func TestHelperProcess(t *testing.T) {
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		return // an ordinary run of the suite
	}
	mode, rest := args[1], args[2:]
	switch mode {
	case "echo": // the rest, one per line; stdin after them
		for _, a := range rest {
			fmt.Println(a)
		}
		in, _ := io.ReadAll(os.Stdin)
		os.Stdout.Write(in)
	case "usage": // writes {"session_id": rest[1], "api_calls": 2} to rest[0], answers "done"
		_ = os.WriteFile(rest[0], []byte(`{"session_id":"`+rest[1]+`","api_calls":2}`), 0o600)
		fmt.Print("done")
	case "env":
		for _, kv := range os.Environ() {
			fmt.Println(kv)
		}
	case "exit": // stderr rest[1], exit rest[0]
		fmt.Fprint(os.Stderr, rest[1])
		code, _ := strconv.Atoi(rest[0])
		os.Exit(code)
	case "big":
		n, _ := strconv.Atoi(rest[0])
		os.Stdout.Write([]byte(strings.Repeat("x", n)))
	case "selfkill":
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	case "block": // block until killed
		for {
			time.Sleep(time.Hour)
		}
	case "orphan": // leave a child in the group that outlives this process, then exit 0
		child := osexec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--", "block")
		child.Stdout, child.Stderr = nil, nil
		if err := child.Start(); err != nil {
			os.Exit(9)
		}
		_ = os.WriteFile(rest[0], []byte(strconv.Itoa(child.Process.Pid)), 0o600)
	case "tree": // start a blocking child in the group, write its pid to rest[0], block
		child := osexec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--", "block")
		if err := child.Start(); err != nil {
			os.Exit(9)
		}
		_ = os.WriteFile(rest[0]+".tmp", []byte(strconv.Itoa(child.Process.Pid)), 0o600)
		_ = os.Rename(rest[0]+".tmp", rest[0])
		for {
			time.Sleep(time.Hour)
		}
	default:
		os.Exit(99)
	}
	os.Exit(0)
}

func newRunner(t *testing.T, cfg Config) *Runner {
	t.Helper()
	if cfg.RunDirBase == "" {
		cfg.RunDirBase = t.TempDir()
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRun_AnswerIsStdoutWithPlaceholdersExpandedOnce(t *testing.T) {
	r := newRunner(t, Config{Argv: helperArgv("echo", "-z", "{prompt}", "run={run_id}", "{agent_key}/{lane}@{backend}:{home}", "{unknown}"),
		ToolsetsArgs: []string{"--toolsets", "{toolsets}"}})
	s := runner.Session{RunID: "r1", AgentKey: "watcher", Lane: runner.LaneReal, Prompt: "say {run_id}", Toolsets: []string{"a", "b"},
		Target: runner.Target{Backend: "engine-a", Home: "home-a"}}
	res, err := r.Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	want := "-z\nsay {run_id}\nrun=r1\nwatcher/real@engine-a:home-a\n{unknown}\n--toolsets\na,b\n"
	if res.Response != want || res.ExitCode != 0 {
		t.Fatalf("response = %q, want %q", res.Response, want)
	}
}

func TestRun_PromptGoesToStdinWithoutAPlaceholder(t *testing.T) {
	r := newRunner(t, Config{Argv: helperArgv("echo"), UsageArgs: []string{"--usage-file", "{usage_path}"}})
	res, err := r.Run(context.Background(), runner.Session{Prompt: "the prompt"})
	if err != nil || res.Response != "the prompt" {
		t.Fatalf("res = %+v, err = %v (no usage path: no usage args)", res, err)
	}
}

func TestRun_ReadsTheUsageReport(t *testing.T) {
	usage := filepath.Join(t.TempDir(), "r1.json")
	r := newRunner(t, Config{Argv: helperArgv("usage"), UsageArgs: []string{"{usage_path}", "sess-9"}})
	res, err := r.Run(context.Background(), runner.Session{RunID: "r1", UsagePath: usage})
	if err != nil || res.Response != "done" || res.SessionID != "sess-9" || res.Usage["api_calls"] != float64(2) {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	// a link where the report should be is not followed
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(usage, link); err != nil {
		t.Fatal(err)
	}
	if u, err := readUsage(link); err == nil || u != nil {
		t.Fatalf("a linked usage report was read: %v %v", u, err)
	}
}

func TestRun_ExitStatusIsClassed(t *testing.T) {
	r := newRunner(t, Config{Argv: helperArgv("exit"), ExitClasses: map[int]runner.Class{75: runner.ConcurrencyLimited}})
	for code, want := range map[int]runner.Class{75: runner.ConcurrencyLimited, 3: runner.TurnFailed} {
		r.cfg.Argv = helperArgv("exit", strconv.Itoa(code), "the reason")
		res, err := r.Run(context.Background(), runner.Session{})
		if runner.ClassOf(err) != want || res.ExitCode != code || res.Stderr != "the reason" || !strings.Contains(err.Error(), "the reason") {
			t.Errorf("exit %d: class %v, res %+v, err %v", code, runner.ClassOf(err), res, err)
		}
	}
}

func TestRun_AnAnswerOverTheCapFails(t *testing.T) {
	r := newRunner(t, Config{Argv: helperArgv("big", "5000"), MaxResponseBytes: 4096})
	res, err := r.Run(context.Background(), runner.Session{})
	if runner.ClassOf(err) != runner.TurnFailed || res.Response != "" {
		t.Fatalf("class %v, response %d bytes", runner.ClassOf(err), len(res.Response))
	}
}

func TestRun_AnExternalSignalIsKilledExternally(t *testing.T) {
	r := newRunner(t, Config{Argv: helperArgv("selfkill")})
	_, err := r.Run(context.Background(), runner.Session{})
	if runner.ClassOf(err) != runner.KilledExternally {
		t.Fatalf("err = %v", err)
	}
}

func TestRun_TheCeilingIsTimeoutCeiling(t *testing.T) {
	r := newRunner(t, Config{Argv: helperArgv("block"), KillGrace: time.Second})
	_, err := r.Run(context.Background(), runner.Session{Limits: runner.Limits{Timeout: 100 * time.Millisecond}})
	if runner.ClassOf(err) != runner.TimeoutCeiling {
		t.Fatalf("err = %v", err)
	}
}

// A cancel ends the whole process group: the session's own child is gone when Run returns.
func TestRun_ACancelKillsTheWholeGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	r := newRunner(t, Config{Argv: helperArgv("tree", pidFile), KillGrace: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := r.Run(ctx, runner.Session{}); done <- err }()
	var pid int
	for deadline := time.Now().Add(30 * time.Second); pid == 0; {
		if data, err := os.ReadFile(pidFile); err == nil {
			pid, _ = strconv.Atoi(string(data))
		} else if time.Now().After(deadline) {
			t.Fatal("the session's child did not start")
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}
	cancel()
	if err := <-done; runner.ClassOf(err) != runner.KilledByController {
		t.Fatalf("err = %v", err)
	}
	if alive(pid) {
		t.Fatalf("the session's child %d outlived the cancel", pid)
	}
}

// alive reports whether pid is a process that is not a zombie.
func alive(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	return i < 0 || i+2 >= len(s) || (s[i+2] != 'Z' && s[i+2] != 'X')
}

// An empty allowlist inherits nothing, and a denied name never reaches the session, whatever the
// allowlist says: a session can print its environment into the answer a caller reads.
func TestRun_NothingInheritedUnlessListedAndDeniedNeverIs(t *testing.T) {
	t.Setenv("HNX_TEST_TOKEN", "the-forwarder-secret")
	t.Setenv("HNX_TEST_OTHER", "x")
	r := newRunner(t, Config{Argv: helperArgv("env")})
	res, err := r.Run(context.Background(), runner.Session{RunID: "r1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Response, "the-forwarder-secret") || strings.Contains(res.Response, "HNX_TEST_OTHER") || strings.Contains("\n"+res.Response, "\nPATH=") {
		t.Errorf("an empty allowlist passed the controller's environment:\n%s", res.Response)
	}
	if !strings.Contains(res.Response, "HNX_RUN_ID=r1") {
		t.Errorf("the session's own variables are missing:\n%s", res.Response)
	}
	cfg := Config{Argv: helperArgv("env"), EnvAllowlist: []string{"HNX_*"}}
	cfg.DenyEnv = []string{"HNX_TEST_TOKEN"}
	r = newRunner(t, cfg)
	res, err = r.Run(context.Background(), runner.Session{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Response, "the-forwarder-secret") || !strings.Contains(res.Response, "HNX_TEST_OTHER=x") {
		t.Errorf("a denied name passed, or the allowlist did not:\n%s", res.Response)
	}
	if e, ok := Covers([]string{"LANG", "HNX_*"}, "HNX_TEST_TOKEN"); !ok || e != "HNX_*" {
		t.Errorf("Covers = %q %v", e, ok)
	}
	if _, ok := Covers(nil, "LANG"); ok {
		t.Error("an empty allowlist covers a name")
	}
}

func TestRun_TheEnvironmentIsTheAllowlistAndTheSession(t *testing.T) {
	t.Setenv("HNX_TEST_KEEP", "1")
	t.Setenv("HNX_TEST_DROP", "1")
	t.Setenv("HNX_RUN_ID", "inherited")
	r := newRunner(t, Config{Argv: helperArgv("env"), EnvAllowlist: []string{"HNX_TEST_K*", "HNX_RUN_ID"}})
	res, err := r.Run(context.Background(), runner.Session{RunID: "r1", GatewayTag: "tag-r1", Servers: map[string]runner.Server{"files": {Command: "files-mcp"}}})
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(res.Response), "\n") {
		k, v, _ := strings.Cut(l, "=")
		env[k] = v
	}
	if env["HNX_TEST_KEEP"] != "1" || env["HNX_RUN_ID"] != "r1" || env["HNX_GATEWAY_TAG"] != "tag-r1" {
		t.Errorf("env = %v", env)
	}
	if _, ok := env["HNX_TEST_DROP"]; ok {
		t.Error("a variable outside the allowlist reached the session")
	}
	if _, ok := env["PATH"]; ok {
		t.Error("PATH reached the session without being allowed")
	}
	if env["HNX_SERVERS_FILE"] == "" {
		t.Error("no servers file for a session with servers")
	}
}

// The servers file holds the session's rendered grants and is gone with the run directory.
func TestRun_TheServersFileHoldsTheGrants(t *testing.T) {
	base := t.TempDir()
	r := newRunner(t, Config{Argv: append(helperArgv("echo"), ""), RunDirBase: base, EnvAllowlist: []string{"PATH"}})
	r.cfg.Argv = []string{"/bin/sh", "-c", `cat "$HNX_SERVERS_FILE"`}
	res, err := r.Run(context.Background(), runner.Session{Servers: map[string]runner.Server{"files": {Command: "files-mcp", Args: []string{"--ro"}}}})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]runner.Server
	if err := json.Unmarshal([]byte(res.Response), &got); err != nil || got["files"].Command != "files-mcp" {
		t.Fatalf("servers = %q, %v", res.Response, err)
	}
	if left, _ := os.ReadDir(base); len(left) != 0 {
		t.Fatalf("run directories left behind: %v", left)
	}
}

func TestNew_Refusals(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no argv":             {},
		"placeholder program": {Argv: []string{"{home}/bin/agent"}},
		"NUL":                 {Argv: []string{"agent", "a\x00b"}},
		"exit 0 classed":      {Argv: []string{"agent"}, ExitClasses: map[int]runner.Class{0: runner.TurnFailed}},
		"exit 256":            {Argv: []string{"agent"}, ExitClasses: map[int]runner.Class{256: runner.TurnFailed}},
		"external class":      {Argv: []string{"agent"}, ExitClasses: map[int]runner.Class{9: runner.KilledExternally}},
		"bare star":           {Argv: []string{"agent"}, EnvAllowlist: []string{"*"}},
		"inner star":          {Argv: []string{"agent"}, EnvAllowlist: []string{"A*B"}},
		"relative run dir":    {Argv: []string{"agent"}, RunDirBase: "runs"},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRun_ACancelledContextStartsNothing(t *testing.T) {
	r := newRunner(t, Config{Argv: helperArgv("echo")})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Run(ctx, runner.Session{}); runner.ClassOf(err) != runner.KilledByController || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

// A descendant left in the group when the session exits is killed with it, and gone (not
// running) by the time Run returns.
func TestRun_TheGroupIsGoneWhenRunReturns(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	r := newRunner(t, Config{Argv: helperArgv("orphan", pidFile)})
	if _, err := r.Run(context.Background(), runner.Session{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(string(data))
	if alive(pid) {
		t.Fatalf("the session's descendant %d is still running after Run returned", pid)
	}
}

// The sweep is bounded: a group that does not go away within the bound is given up on.
func TestSweepGroup_IsBounded(t *testing.T) {
	cmd := osexec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if sweepGroup(cmd.Process.Pid, 0) {
		t.Fatal("a running group read as gone")
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if !sweepGroup(cmd.Process.Pid, 30*time.Second) {
		t.Fatal("a killed group was never seen gone")
	}
}

// A descendant that leaves the session's group (setsid) is not this process's to reap: it is
// never left as this process's zombie.
func TestRun_ASetsidDescendantIsNoZombieOfOurs(t *testing.T) {
	// the leader answers only once the descendant is in its own session
	ready := filepath.Join(t.TempDir(), "ready")
	script := `setsid sh -c 'echo $$ > "$1"; exec sleep 0.3' - "$0" & while [ ! -s "$0" ]; do :; done; cat "$0"`
	r := newRunner(t, Config{Argv: []string{"/bin/sh", "-c", script, ready}, EnvAllowlist: []string{"PATH"}})
	res, err := r.Run(context.Background(), runner.Session{})
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(res.Response))
	if err != nil {
		t.Fatalf("response %q", res.Response)
	}
	for deadline := time.Now().Add(30 * time.Second); alive(pid); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the descendant never exited")
		}
	}
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil && strings.Contains(string(data), fmt.Sprintf("\nPPid:\t%d\n", os.Getpid())) {
		t.Fatalf("the exited descendant %d is a zombie of this process", pid)
	}
}

// A program that exits cleanly while a descendant outside its group keeps its stdout open has given
// no complete answer: the session fails TurnFailed once the grace has run out.
func TestRun_OutputHeldOpenAfterACleanExitIsTurnFailed(t *testing.T) {
	// the leader waits until the descendant is in its own session before it answers and exits
	ready := filepath.Join(t.TempDir(), "ready")
	script := `setsid sh -c 'echo x > "$1"; exec sleep 3' - "$0" & while [ ! -s "$0" ]; do :; done; echo partial`
	r := newRunner(t, Config{Argv: []string{"/bin/sh", "-c", script, ready}, EnvAllowlist: []string{"PATH"}, KillGrace: 100 * time.Millisecond})
	res, err := r.Run(context.Background(), runner.Session{})
	if runner.ClassOf(err) != runner.TurnFailed || res.Response != "" {
		t.Fatalf("class %v, response %q, err %v", runner.ClassOf(err), res.Response, err)
	}
}
