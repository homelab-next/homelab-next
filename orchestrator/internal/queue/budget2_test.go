// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/backends"
	"github.com/homelab-next/homelab-next/orchestrator/internal/grants"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner/runnertest"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// A shutdown's retry is bounded like a kill's: a retry that is itself shut down gets none.
func TestShutdownRetry_ARetryShutDownIsNotRetriedAgain(t *testing.T) {
	r := newRig(t, rigOptions{runner: runnertest.New(runnertest.Block(make(chan struct{}), "", nil))})
	j := &store.Job{RunID: "retry-1", AgentKey: defaultProfile, Priority: 50, State: store.StateQueued,
		CreatedAt: time.Now().UTC(), TaskDescription: "t", RetryOfRunID: "parent-1"}
	if err := r.st.CreateJob(&store.Job{RunID: "parent-1", AgentKey: defaultProfile, Priority: 50, State: store.StateFailed, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := r.st.CreateJob(j); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := r.tickAsync(ctx)
	r.waitState("retry-1", store.StateRunning)
	cancel()
	waitClosed(t, done, "the shut-down retry")
	if got := r.job("retry-1"); got.State != store.StateFailed || got.RetriedByRunID != "" {
		t.Fatalf("shut-down retry = %s retried by %q", got.State, got.RetriedByRunID)
	}
}

// A shut-down job whose profile already ran a second attempt gets no shutdown retry either.
func TestShutdownRetry_NotAfterAProfileRetry(t *testing.T) {
	var n atomic.Int32
	run := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		if n.Add(1) == 1 {
			return &runner.Result{}, runner.Wrap(runner.TurnFailed, errors.New("first"))
		}
		<-ctx.Done()
		return &runner.Result{}, runner.Wrap(runner.KilledByController, ctx.Err())
	})
	r := newRig(t, rigOptions{runner: run, profiles: profileWith("max_attempts: 2\n")})
	r.submit("run-1", defaultProfile)
	ctx, cancel := context.WithCancel(context.Background())
	done := r.tickAsync(ctx)
	for n.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	waitClosed(t, done, "the shut-down job")
	if got := r.job("run-1"); got.RetriedByRunID != "" {
		t.Fatalf("a second attempt shut down was retried as %q", got.RetriedByRunID)
	}
}

// A local-only job keeps going back to the queue while its backends are down, at most
// MaxBackendDownRequeues times; then it fails backend-down. Its prompt's provenance is its first
// dispatch's.
func TestBackendDownRequeue_IsBoundedThenFailsBackendDown(t *testing.T) {
	h := newHealth(t)
	run := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		h.ok.Store(false)
		return &runner.Result{}, runner.MarkAbsent(errors.New("connection refused"))
	})
	r := newRig(t, rigOptions{runner: run, backends: []backends.Backend{{Name: "engine-a", HealthURL: h.URL}},
		profiles: map[string]string{defaultProfile: "local_only: true\n"}})
	r.submit("run-1", defaultProfile)
	var sha string
	for i := 0; i <= MaxBackendDownRequeues; i++ {
		h.ok.Store(true)
		probe(r)
		r.tick()
		j := r.job("run-1")
		if i == 0 {
			sha = j.PromptSHA256
		}
		if j.PromptSHA256 != sha {
			t.Fatalf("requeue %d rewrote the provenance", i)
		}
		if i < MaxBackendDownRequeues && (j.State != store.StateQueued || j.Attempts != 0) {
			t.Fatalf("requeue %d: %s attempts=%d", i, j.State, j.Attempts)
		}
	}
	j := r.job("run-1")
	if j.State != store.StateFailed || j.FailureClass != store.FailureBackendDown {
		t.Fatalf("after %d requeues the job is %s %q", MaxBackendDownRequeues, j.State, j.FailureClass)
	}
	if n := len(run.Sessions()); n != MaxBackendDownRequeues+1 {
		t.Fatalf("%d sessions", n)
	}
	r.pool.balanced(t)
}

// A requeued attempt does not spend the job's first attempt: a kill after it still gets its
// automatic retry.
func TestBackendDownRequeue_DoesNotSpendTheKillRetry(t *testing.T) {
	h := newHealth(t)
	var n atomic.Int32
	run := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		if n.Add(1) == 1 {
			h.ok.Store(false)
			return &runner.Result{}, runner.MarkAbsent(errors.New("connection refused"))
		}
		return &runner.Result{}, runner.Wrap(runner.KilledExternally, errors.New("killed"))
	})
	r := newRig(t, rigOptions{runner: run, backends: []backends.Backend{{Name: "engine-a", HealthURL: h.URL}},
		profiles: map[string]string{defaultProfile: "local_only: true\n"}})
	r.submit("run-1", defaultProfile)
	r.tick()
	h.ok.Store(true)
	probe(r)
	r.tick()
	if j := r.job("run-1"); j.State != store.StateFailed || j.RetriedByRunID == "" {
		t.Fatalf("job = %s retried by %q: the requeued attempt spent the kill's retry", j.State, j.RetriedByRunID)
	}
}

// The deadline passing just as an attempt fails, with another attempt due, is the deadline class,
// never the attempt's own failure.
func TestBudget_DeadlineBeforeTheRetryDecisionIsTheDeadline(t *testing.T) {
	run := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		<-ctx.Done()
		time.Sleep(5 * time.Millisecond)
		// A failure the runner reports as its own turn's, after the deadline ended the job.
		return &runner.Result{}, runner.Wrap(runner.TurnFailed, errors.New("the turn failed"))
	})
	r := newRig(t, rigOptions{runner: run, jobLimit: 30 * time.Millisecond, profiles: profileWith("max_attempts: 3\n")})
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.FailureClass != store.FailureDeadline || !strings.HasPrefix(j.LocalFailedReason, "deadline") {
		t.Fatalf("class %q reason %q", j.FailureClass, j.LocalFailedReason)
	}
}

// With no job deadline configured the ceiling still bounds a job.
func TestJobCeiling_AppliesWhenThePoolSetsNoDeadline(t *testing.T) {
	r := newRig(t, rigOptions{runner: runnertest.New(runnertest.Block(make(chan struct{}), "", nil)),
		tweak: func(c *Config) { c.JobCeiling = 30 * time.Millisecond }})
	r.submit("run-1", defaultProfile)
	start := time.Now()
	r.tick()
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("the job ran %s past its ceiling", el)
	}
	if j := r.job("run-1"); j.FailureClass != store.FailureDeadline {
		t.Fatalf("class %q", j.FailureClass)
	}
	if DefaultJobCeiling <= 0 {
		t.Fatal("no default ceiling")
	}
}

// A reason found before any attempt is bounded: a grants error can quote a value.
func TestFailRunning_ReasonIsBounded(t *testing.T) {
	cat, err := grants.ParseCatalog([]byte(testCatalog), testZones)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("v", 3000)
	r := newRig(t, rigOptions{profiles: profileWith("grants:\n  real: [{name: n, kind: notes, env: {NOTES_NAME: \"" + long + "\"}}]\n  shadow: [{name: n, kind: notes}]\n"),
		tweak: func(c *Config) { c.Grants = cat }})
	r.submit("run-1", defaultProfile)
	r.tick()
	j := r.job("run-1")
	if j.State != store.StateFailed || len(j.LocalFailedReason) > maxPreparedReason {
		t.Fatalf("job = %s reason of %d bytes", j.State, len(j.LocalFailedReason))
	}
}
