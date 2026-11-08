// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/grants"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner/runnertest"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// The findings check: a profile whose path scope has a findings prefix per lane files one finding
// per run, so a clean exit that wrote nothing there fails.
const findingsProfile = "path_scope:\n  writable_prefixes: [notes/findings/watcher/, notes/findings/watcher-shadow/]\n"

// writeFinding writes a finding into dir/prefix during the session, then answers.
func writeFinding(root, prefix string) runnertest.Step {
	return func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		dir := filepath.Join(root, prefix)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, s.RunID+".md"), []byte("finding"), 0o600); err != nil {
			return nil, err
		}
		return &runner.Result{Response: "filed"}, nil
	}
}

func findingsRig(t *testing.T, step runnertest.Step, root string) *rig {
	return newRig(t, rigOptions{runner: runnertest.New(step), profiles: profileWith(findingsProfile),
		tweak: func(c *Config) { c.TreeRoot = root }})
}

func TestScheduler_CleanExitWithNoFindingIsMarkedFailedWhenVerified(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "notes/findings/watcher"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := findingsRig(t, runnertest.Answer("I did it, honestly"), root)
	r.submit("run-1", defaultProfile)
	r.tick()
	j := r.job("run-1")
	if j.State != store.StateFailed || j.FailureClass != store.FailureHandlerError || j.ResponseBody != "" ||
		!strings.HasPrefix(j.LocalFailedReason, "handler-error: the run ended cleanly but wrote nothing") {
		t.Fatalf("job = %s %q %q response=%q", j.State, j.FailureClass, j.LocalFailedReason, j.ResponseBody)
	}
}

func TestScheduler_CleanExitWithFindingWrittenStaysDone(t *testing.T) {
	root := t.TempDir()
	r := findingsRig(t, writeFinding(root, "notes/findings/watcher/"), root)
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.State != store.StateDone {
		t.Fatalf("job = %s %q", j.State, j.LocalFailedReason)
	}
}

// A file older than the dispatch is not this run's finding.
func TestScheduler_OldFindingDoesNotCount(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "notes/findings/watcher")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "yesterday.md")
	if err := os.WriteFile(old, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	r := findingsRig(t, runnertest.Answer("done"), root)
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.State != store.StateFailed {
		t.Fatalf("an old file counted: %s", j.State)
	}
}

// The findings directory not existing at all means nothing was ever written there.
func TestScheduler_CleanExitWithMissingFindingsDirIsMarkedFailed(t *testing.T) {
	r := findingsRig(t, runnertest.Answer("done"), t.TempDir())
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.State != store.StateFailed {
		t.Fatalf("job = %s", j.State)
	}
}

// Without a tree root, or for a profile with no findings prefix, nothing is checked.
func TestScheduler_VerificationDisabledByDefaultPreservesOldBehavior(t *testing.T) {
	r := newRig(t, rigOptions{profiles: profileWith(findingsProfile)})
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.State != store.StateDone {
		t.Fatalf("with no tree root: %s", j.State)
	}
	r2 := newRig(t, rigOptions{tweak: func(c *Config) { c.TreeRoot = t.TempDir() }})
	r2.submit("run-2", defaultProfile)
	r2.tick()
	if j := r2.job("run-2"); j.State != store.StateDone {
		t.Fatalf("with no findings prefix: %s", j.State)
	}
}

// A shadow run is checked in its lane's own directory: a real finding never counts for it.
func TestScheduler_VerifyFindingWrittenLooksInTheLanesDirectory(t *testing.T) {
	root := t.TempDir()
	r := findingsRig(t, writeFinding(root, "notes/findings/watcher/"), root)
	j := &store.Job{RunID: "run-s", AgentKey: defaultProfile, Priority: 50, State: store.StateQueued, Shadow: true,
		CreatedAt: time.Now().UTC(), TaskDescription: "t"}
	if err := r.st.CreateJob(j); err != nil {
		t.Fatal(err)
	}
	r.tick()
	if got := r.job("run-s"); got.State != store.StateFailed {
		t.Fatalf("a real-lane finding counted for a shadow run: %s", got.State)
	}
	r2 := findingsRig(t, writeFinding(root, "notes/findings/watcher-shadow/"), root)
	if err := r2.st.CreateJob(j); err != nil {
		t.Fatal(err)
	}
	r2.tick()
	if got := r2.job("run-s"); got.State != store.StateDone {
		t.Fatalf("a shadow finding did not count: %s", got.State)
	}
}

// A link in place of the prefix's directory is never followed: the check fails, whatever the
// link's target holds.
func TestScheduler_FindingsCheckRefusesALinkedPrefix(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "notes/findings"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "notes/findings/watcher")); err != nil {
		t.Fatal(err)
	}
	r := findingsRig(t, writeFinding(outside, ""), root)
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.State != store.StateFailed {
		t.Fatalf("a finding behind a linked prefix counted: %s", j.State)
	}
	inside := filepath.Join(root, "notes/elsewhere")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "notes/findings/watcher")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(inside, filepath.Join(root, "notes/findings/watcher")); err != nil {
		t.Fatal(err)
	}
	r2 := findingsRig(t, writeFinding(inside, ""), root)
	r2.submit("run-2", defaultProfile)
	r2.tick()
	if j := r2.job("run-2"); j.State != store.StateFailed {
		t.Fatalf("a link inside the root counted: %s", j.State)
	}
}

// A file dated in the future is no proof the run wrote it.
func TestScheduler_FutureDatedFindingDoesNotCount(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "notes/findings/watcher")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "planted.md")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(24 * time.Hour)
	if err := os.Chtimes(f, later, later); err != nil {
		t.Fatal(err)
	}
	r := findingsRig(t, runnertest.Answer("done"), root)
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.State != store.StateFailed {
		t.Fatalf("a future-dated file counted: %s", j.State)
	}
}

const testCatalog = `kinds:
  notes:
    command: /usr/local/bin/notes-mcp
    env: {NOTES_TIER: local}
    allowed_env: [NOTES_NAME]
    free_env: {NOTES_NAME: name}
  collector:
    command: /usr/local/bin/collector-mcp
    allowed_env: [COLLECTOR_NAME]
    free_env: {COLLECTOR_NAME: name}
`

const grantsProfile = `grants:
  real: [{name: notes-real, kind: notes, env: {NOTES_NAME: real}}, {name: collector-real, kind: collector}]
  shadow: [{name: notes-shadow, kind: notes, env: {NOTES_NAME: shadow}}]
`

func grantsRig(t *testing.T, run runner.Runner, extra string) *rig {
	t.Helper()
	cat, err := grants.ParseCatalog([]byte(testCatalog), testZones)
	if err != nil {
		t.Fatal(err)
	}
	return newRig(t, rigOptions{runner: run, profiles: profileWith(grantsProfile + extra), tweak: func(c *Config) { c.Grants = cat }})
}

// A profile with grants gets exactly its lane's rendered servers, and its toolsets are their
// names.
func TestScheduler_GrantsEnabled_JobSeesOnlyItsGrantedServers(t *testing.T) {
	run := runnertest.New()
	r := grantsRig(t, run, "")
	r.submit("run-1", defaultProfile)
	r.tick()
	s := run.Sessions()
	if len(s) != 1 || len(s[0].Servers) != 2 || s[0].Servers["notes-real"].Command != "/usr/local/bin/notes-mcp" ||
		s[0].Servers["notes-real"].Env["NOTES_NAME"] != "real" || !reflect.DeepEqual(s[0].Toolsets, []string{"collector-real", "notes-real"}) {
		t.Fatalf("session = %+v", s)
	}
}

// A profile with no grants block passes nil servers: the runner's own default set.
func TestScheduler_GrantsDisabled_DispatchUnchanged(t *testing.T) {
	run := runnertest.New()
	cat, _ := grants.ParseCatalog([]byte(testCatalog), testZones)
	r := newRig(t, rigOptions{runner: run, tweak: func(c *Config) { c.Grants = cat }})
	r.submit("run-1", defaultProfile)
	r.tick()
	if s := run.Sessions(); len(s) != 1 || s[0].Servers != nil || !reflect.DeepEqual(s[0].Toolsets, []string{"notes", "web"}) {
		t.Fatalf("session = %+v", s)
	}
}

// Every attempt of a max_attempts retry carries the same servers.
func TestScheduler_GrantsApplyToEveryRetryAttempt(t *testing.T) {
	run := runnertest.New(runnertest.Fail(runner.TurnFailed, "a"), runnertest.Answer("ok"))
	r := grantsRig(t, run, "max_attempts: 2\n")
	r.submit("run-1", defaultProfile)
	r.tick()
	s := run.Sessions()
	if len(s) != 2 || !reflect.DeepEqual(s[0].Servers, s[1].Servers) || len(s[1].Servers) != 2 {
		t.Fatalf("sessions = %+v", s)
	}
}

// A profile with grants and no catalog configured fails before any session.
func TestScheduler_GrantsWithoutACatalogFail(t *testing.T) {
	run := runnertest.New()
	r := newRig(t, rigOptions{runner: run, profiles: profileWith(grantsProfile)})
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.State != store.StateFailed || !strings.Contains(j.LocalFailedReason, "no grants catalog") || len(run.Sessions()) != 0 {
		t.Fatalf("job = %s %q, %d sessions", j.State, j.LocalFailedReason, len(run.Sessions()))
	}
}

// The prompt carries the contracts it was given (default ones when none are), and its provenance
// is stored.
func TestScheduler_PromptCarriesTheContracts(t *testing.T) {
	run := runnertest.New()
	r := newRig(t, rigOptions{runner: run, tweak: func(c *Config) { c.Contracts = nil }})
	r.submit("run-1", defaultProfile)
	r.tick()
	p := run.Sessions()[0].Prompt
	if !strings.Contains(p, "[required-tool-call]") || !strings.Contains(p, "[loop-detection]") {
		t.Fatalf("the default contracts are missing: %q", p)
	}
}
