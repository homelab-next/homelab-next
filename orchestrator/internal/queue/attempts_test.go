// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/backends"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner/runnertest"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

func profileWith(extra string) map[string]string { return map[string]string{defaultProfile: extra} }

// max_attempts runs the chain again until it succeeds, under the same run id, each attempt with
// its own usage path.
func TestMaxAttempts_RetriesUntilSuccess(t *testing.T) {
	run := runnertest.New(runnertest.Fail(runner.TurnFailed, "one"), runnertest.Fail(runner.TurnFailed, "two"), runnertest.Answer("third time"))
	r := newRig(t, rigOptions{runner: run, profiles: profileWith("max_attempts: 3\n"),
		tweak: func(c *Config) { c.UsageDir = filepath.Join(t.TempDir(), "u") }})
	r.submit("run-1", defaultProfile)
	r.tick()
	j := r.job("run-1")
	if j.State != store.StateDone || j.Attempts != 3 || j.ResponseBody != "third time" {
		t.Fatalf("job = %s attempts=%d %q", j.State, j.Attempts, j.ResponseBody)
	}
	s := run.Sessions()
	if len(s) != 3 {
		t.Fatalf("%d sessions", len(s))
	}
	for i, want := range []string{"run-1.json", "run-1.a2.json", "run-1.a3.json"} {
		if s[i].RunID != "run-1" || filepath.Base(s[i].UsagePath) != want || s[i].GatewayTag != "hnx/run-1" {
			t.Errorf("attempt %d: run %q usage %q tag %q", i+1, s[i].RunID, s[i].UsagePath, s[i].GatewayTag)
		}
	}
	if q, _ := r.st.ListByState(store.StateQueued); len(q) != 0 {
		t.Error("a retry created a new run")
	}
	r.pool.balanced(t)
}

// max_attempts is a bound: a job that keeps failing stops there and fails.
func TestMaxAttempts_IsABound(t *testing.T) {
	run := runnertest.New(runnertest.Fail(runner.TurnFailed, "always"))
	r := newRig(t, rigOptions{runner: run, profiles: profileWith("max_attempts: 2\n")})
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.State != store.StateFailed || j.Attempts != 2 || len(run.Sessions()) != 2 {
		t.Fatalf("job = %s attempts=%d sessions=%d", j.State, j.Attempts, len(run.Sessions()))
	}
}

// With no max_attempts a job has one attempt.
func TestMaxAttempts_DefaultIsOneAttempt(t *testing.T) {
	run := runnertest.New(runnertest.Fail(runner.TurnFailed, "once"))
	r := newRig(t, rigOptions{runner: run})
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.Attempts != 1 || len(run.Sessions()) != 1 {
		t.Fatalf("attempts=%d sessions=%d", j.Attempts, len(run.Sessions()))
	}
}

// sleepThenFail fails as a turn after d, or as a killed session when ctx ends first.
func sleepThenFail(d time.Duration) runnertest.Step {
	return func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		select {
		case <-time.After(d):
			return &runner.Result{}, runner.Wrap(runner.TurnFailed, errors.New("transient"))
		case <-ctx.Done():
			return &runner.Result{}, runner.Wrap(runner.KilledByController, ctx.Err())
		}
	}
}

// The job's deadline spans every attempt: a retry gets no fresh budget, and the job ends with
// class deadline, never retried or requeued.
func TestBudget_JobDeadlineSpansProfileRetries(t *testing.T) {
	run := runnertest.New(sleepThenFail(200 * time.Millisecond))
	r := newRig(t, rigOptions{runner: run, jobLimit: 300 * time.Millisecond, profiles: profileWith("local_only: true\nmax_attempts: 3\n")})
	r.submit("run-1", defaultProfile)
	start := time.Now()
	r.tick()
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("the job ran %s past its 300ms deadline", el)
	}
	j := r.job("run-1")
	if n := len(run.Sessions()); n > 2 {
		t.Errorf("%d sessions: the deadline allows at most 2 starts", n)
	}
	if j.State != store.StateFailed || j.FailureClass != store.FailureDeadline {
		t.Fatalf("job = %s %q", j.State, j.FailureClass)
	}
	if q, _ := r.st.ListByState(store.StateQueued); len(q) != 0 {
		t.Error("a spent deadline was requeued")
	}
	r.pool.balanced(t)
}

// An attempt's ceiling in the local leg is still a spent budget when the cloud leg failed after
// it: class budget, no further attempt, no automatic retry.
func TestBudget_TimeoutCeilingSurvivesCloudFallbackFailure(t *testing.T) {
	run := runnertest.New(runnertest.On(map[string]runnertest.Step{
		"engine-a": runnertest.Fail(runner.TimeoutCeiling, "ceiling"),
		"cloud":    runnertest.Fail(runner.KilledExternally, "killed"),
	}, nil))
	r := newRig(t, rigOptions{runner: run, cloud: "cloud-home", profiles: profileWith("max_attempts: 3\n")})
	r.submit("run-1", defaultProfile)
	r.tick()
	j := r.job("run-1")
	if j.State != store.StateFailed || j.FailureClass != store.FailureBudget || j.Attempts != 1 {
		t.Fatalf("job = %s %q attempts=%d", j.State, j.FailureClass, j.Attempts)
	}
	if q, _ := r.st.ListByState(store.StateQueued); len(q) != 0 {
		t.Error("a spent budget was retried")
	}
}

// A kill's automatic retry is one extra run: a profile that already ran more than one attempt
// gets none; a single-attempt profile gets exactly one, and that retry is never retried again.
func TestBudget_CapacityRequeueDoesNotStackOnProfileRetries(t *testing.T) {
	run := runnertest.New(runnertest.Fail(runner.KilledExternally, "killed"))
	r := newRig(t, rigOptions{runner: run, profiles: profileWith("max_attempts: 3\n")})
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.State != store.StateFailed || j.Attempts != 3 || j.RetriedByRunID != "" {
		t.Fatalf("job = %s attempts=%d retried by %q", j.State, j.Attempts, j.RetriedByRunID)
	}
}

func TestBudget_CapacityRequeueKeptForSingleAttemptProfiles(t *testing.T) {
	run := runnertest.New(runnertest.Fail(runner.KilledExternally, "killed"))
	r := newRig(t, rigOptions{runner: run})
	r.submit("run-1", defaultProfile)
	r.tick()
	j := r.job("run-1")
	if j.State != store.StateFailed || j.FailureClass != store.FailureHandlerError || j.RetriedByRunID == "" {
		t.Fatalf("job = %s %q retried by %q", j.State, j.FailureClass, j.RetriedByRunID)
	}
	r.tick()
	retry := r.job(j.RetriedByRunID)
	if retry.State != store.StateFailed || retry.RetryOfRunID != "run-1" || retry.RetriedByRunID != "" {
		t.Fatalf("retry = %s of %q retried by %q", retry.State, retry.RetryOfRunID, retry.RetriedByRunID)
	}
	r.pool.balanced(t)
}

// A signal the controller did not send, on a real process: the run is handler-error and retried
// once; the killed process's group is gone.
func TestBudget_ExternalKillIsHandlerErrorButRequeuedOnce(t *testing.T) {
	pr := &procRunner{mode: "hang", dir: t.TempDir()}
	r := newRig(t, rigOptions{runner: pr})
	r.submit("run-1", defaultProfile)
	done := r.tickAsync(context.Background())
	pid, child := pr.sessionPids(t, "run-1", 0)
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, done, "the killed job's executor")
	waitGone(t, pid, child)
	j := r.job("run-1")
	if j.State != store.StateFailed || j.FailureClass != store.FailureHandlerError || j.RetriedByRunID == "" {
		t.Fatalf("job = %s %q retried by %q", j.State, j.FailureClass, j.RetriedByRunID)
	}
	r.pool.balanced(t)
}

// Spend covers every attempt and every leg: the usage files of each session are summed.
func TestBudget_SpendCoversEveryAttempt(t *testing.T) {
	u := map[string]any{"input_tokens": float64(10), "output_tokens": float64(1), "cost_usd": 0.5}
	run := runnertest.New(withUsage(u, runnertest.Fail(runner.TurnFailed, "a")), withUsage(u, runnertest.Fail(runner.TurnFailed, "b")), withUsage(u, runnertest.Answer("ok")))
	r := newRig(t, rigOptions{runner: run, profiles: profileWith("max_attempts: 3\n"), tweak: func(c *Config) { c.UsageDir = t.TempDir() }})
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.InputTokens != 30 || j.OutputTokens != 3 || j.CostUSD != 1.5 {
		t.Fatalf("spend = in %d out %d cost %v, want 30, 3, 1.5", j.InputTokens, j.OutputTokens, j.CostUSD)
	}
}

func TestBudget_SpendCoversLocalAndCloudLegs(t *testing.T) {
	run := runnertest.New(runnertest.On(map[string]runnertest.Step{
		"engine-a": withUsage(map[string]any{"input_tokens": float64(5)}, runnertest.Fail(runner.BackendFault, "reset")),
		"cloud":    withUsage(map[string]any{"input_tokens": float64(7)}, runnertest.Answer("ok")),
	}, nil))
	r := newRig(t, rigOptions{runner: run, cloud: "cloud-home", tweak: func(c *Config) { c.UsageDir = t.TempDir() }})
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.InputTokens != 12 || !j.CloudFallbackUsed {
		t.Fatalf("input tokens %d cloud %v, want 12 over both legs", j.InputTokens, j.CloudFallbackUsed)
	}
}

// A cancel moves the row before it cancels the context; an attempt that failed in between starts
// no further session.
func TestBudget_NoRetryAfterCancelFlippedTheRow(t *testing.T) {
	var st *store.Store
	run := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		if err := st.UpdateState(s.RunID, store.StateRunning, store.StateCancelled); err != nil {
			return nil, err
		}
		return &runner.Result{}, runner.Wrap(runner.TurnFailed, errors.New("failed as the cancel landed"))
	})
	r := newRig(t, rigOptions{runner: run, profiles: profileWith("max_attempts: 3\n")})
	st = r.st
	r.submit("run-1", defaultProfile)
	r.tick()
	if n := len(run.Sessions()); n != 1 {
		t.Fatalf("%d sessions after the cancel", n)
	}
	if j := r.job("run-1"); j.State != store.StateCancelled {
		t.Fatalf("job = %s", j.State)
	}
	r.pool.balanced(t)
}

func TestRetryBackoff_IsBoundedAndGrows(t *testing.T) {
	if retryBackoff(2) != time.Second || retryBackoff(3) != 2*time.Second || retryBackoff(100) != 5*time.Second {
		t.Fatalf("backoff = %v %v %v", retryBackoff(2), retryBackoff(3), retryBackoff(100))
	}
}

// A retry honours a drain: the drained reservation is given back and, with no other backend,
// the job goes back to queued with its attempts kept; undrained, it resumes its count.
func TestBudget_RetryHonoursDrain_RequeuesWhenNothingElse(t *testing.T) {
	var policy *backends.Policy
	var n atomic.Int32
	run := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		if n.Add(1) == 1 {
			if _, err := policy.SetDrained("engine-a", true); err != nil {
				return nil, err
			}
			return &runner.Result{}, runner.Wrap(runner.TurnFailed, errors.New("first attempt"))
		}
		return &runner.Result{Response: "second"}, nil
	})
	r := newRig(t, rigOptions{runner: run, profiles: profileWith("max_attempts: 3\n")})
	policy = r.policy
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.State != store.StateQueued || j.Attempts != 1 {
		t.Fatalf("job = %s attempts=%d, want back to queued with 1 spent", j.State, j.Attempts)
	}
	r.tick()
	if j := r.job("run-1"); j.State != store.StateQueued {
		t.Fatalf("admitted onto a drained backend: %s", j.State)
	}
	if _, err := policy.SetDrained("engine-a", false); err != nil {
		t.Fatal(err)
	}
	r.tick()
	if j := r.job("run-1"); j.State != store.StateDone || j.Attempts != 2 {
		t.Fatalf("job = %s attempts=%d", j.State, j.Attempts)
	}
	r.pool.balanced(t)
}

func TestBudget_RetryHonoursDrain_MovesToAnotherBackend(t *testing.T) {
	var policy *backends.Policy
	var n atomic.Int32
	run := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		switch n.Add(1) {
		case 1: // the reserved backend: drained while its attempt fails
			if _, err := policy.SetDrained(s.Target.Backend, true); err != nil {
				return nil, err
			}
			return &runner.Result{}, runner.Wrap(runner.TurnFailed, errors.New("first"))
		case 2: // the chain's next backend, in the same Call
			return &runner.Result{}, runner.Wrap(runner.TurnFailed, errors.New("second"))
		}
		return &runner.Result{Response: "moved"}, nil
	})
	r := newRig(t, rigOptions{runner: run, profiles: profileWith("max_attempts: 2\nlocal_only: true\n"),
		backends: []backends.Backend{{Name: "engine-a"}, {Name: "engine-b"}}})
	policy = r.policy
	r.submit("run-1", defaultProfile)
	r.tick()
	s := run.Sessions()
	j := r.job("run-1")
	if j.State != store.StateDone || len(s) != 3 || s[2].Target.Backend == s[0].Target.Backend {
		t.Fatalf("job = %s, targets %v", j.State, targets(s))
	}
	if len(r.pool.calls) != 2 || r.pool.calls[0] != s[0].Target.Backend || r.pool.calls[1] != s[2].Target.Backend {
		t.Errorf("Call's reserved backends = %v, targets %v: want a fresh reservation for the retry", r.pool.calls, targets(s))
	}
	r.pool.balanced(t)
}

func targets(ss []runner.Session) []string {
	var out []string
	for _, s := range ss {
		out = append(out, s.Target.Backend)
	}
	return out
}

// A session's text never picks the class: output naming every retryable condition, on a failure
// with no class, is still handler-error.
func TestBudget_ModelOutputNeverChoosesTheFailureClass(t *testing.T) {
	text := "backend unreachable: connection refused; timed out; stalled; signal: killed; context deadline exceeded"
	run := runnertest.New(func(context.Context, runner.Session) (*runner.Result, error) {
		return &runner.Result{Response: text, Stderr: text}, errors.New(text)
	})
	r := newRig(t, rigOptions{runner: run})
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.FailureClass != store.FailureHandlerError || j.RetriedByRunID != "" {
		t.Fatalf("class %q retried by %q: the text chose", j.FailureClass, j.RetriedByRunID)
	}
}

// A failed job's automatic retry is created in the failing transaction, so its failed event
// already names it.
func TestBudget_FailedEventNamesTheSameTransactionAutoRetry(t *testing.T) {
	run := runnertest.New(runnertest.Fail(runner.KilledExternally, "killed"), runnertest.Block(make(chan struct{}), "", nil))
	r := newRig(t, rigOptions{runner: run, outbox: true})
	r.submit("run-1", defaultProfile)
	r.tick()
	j := r.job("run-1")
	failed := outboxEvent(t, r.st, "run-1", EventJobFailed)
	data := failed["data"].(map[string]any)
	if data["auto_retry_scheduled"] != true || data["retried_by_run_id"] != j.RetriedByRunID || j.RetriedByRunID == "" {
		t.Fatalf("failed event data = %v (retry %q)", data, j.RetriedByRunID)
	}
}

// A run cut off by a controller shutdown (its context cancelled, the row still running) is
// retried once as a fresh run; a run past its own deadline is not.
func TestShutdownRetry_OnlyForCanceledContext(t *testing.T) {
	r := newRig(t, rigOptions{runner: runnertest.New(runnertest.Block(make(chan struct{}), "", nil))})
	r.submit("run-1", defaultProfile)
	ctx, cancel := context.WithCancel(context.Background())
	done := r.tickAsync(ctx)
	r.waitState("run-1", store.StateRunning)
	cancel()
	waitClosed(t, done, "the shut-down job")
	j := r.job("run-1")
	if j.State != store.StateFailed || j.FailureClass != store.FailureCapacity || j.RetriedByRunID == "" {
		t.Fatalf("shut-down job = %s %q retried by %q", j.State, j.FailureClass, j.RetriedByRunID)
	}
	if retry := r.job(j.RetriedByRunID); retry.State != store.StateQueued || retry.TaskDescription != j.TaskDescription {
		t.Fatalf("retry = %+v", retry)
	}

	r2 := newRig(t, rigOptions{runner: runnertest.New(runnertest.Block(make(chan struct{}), "", nil)), jobLimit: 50 * time.Millisecond})
	r2.submit("run-2", defaultProfile)
	r2.tick()
	if j := r2.job("run-2"); j.FailureClass != store.FailureDeadline || j.RetriedByRunID != "" {
		t.Fatalf("past-deadline job = %q retried by %q", j.FailureClass, j.RetriedByRunID)
	}
	if !strings.HasPrefix(r2.job("run-2").LocalFailedReason, "deadline: ") {
		t.Errorf("reason = %q", r2.job("run-2").LocalFailedReason)
	}
}
