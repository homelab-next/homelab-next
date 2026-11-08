// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/backends"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner/runnertest"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// signalled closes started when the session begins, then runs then.
func signalled(started chan struct{}, then runnertest.Step) runnertest.Step {
	var once sync.Once
	return func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		once.Do(func() { close(started) })
		return then(ctx, s)
	}
}

// cancel is the API's cancel: the row first, then the executor's context.
func (r *rig) cancel(id string) bool {
	r.t.Helper()
	if err := r.st.UpdateState(id, store.StateRunning, store.StateCancelled); err != nil {
		r.t.Fatal(err)
	}
	return r.sch.CancelRun(id)
}

// A cancel while running defers the finished record to the executor, which emits it after its
// final writes: the record carries the run's usage.
func TestCancelRunning_FinishedWaitsForTheExecutorsFinalWrites(t *testing.T) {
	usage := map[string]any{"input_tokens": float64(77)}
	started := make(chan struct{})
	block := withUsage(usage, signalled(started, runnertest.Block(make(chan struct{}), "", nil)))
	r := newRig(t, rigOptions{runner: runnertest.New(block), outbox: true, tweak: func(c *Config) { c.UsageDir = t.TempDir() }})
	r.submit("run-1", defaultProfile)
	done := r.tickAsync(context.Background())
	waitClosed(t, started, "the session's start")
	if !r.cancel("run-1") {
		t.Fatal("no live executor")
	}
	waitClosed(t, done, "the cancelled executor")
	f := outboxEvent(t, r.st, "run-1", EventJobFinished)
	d := f["data"].(map[string]any)
	if d["outcome"] != OutcomeCancelled || d["usage"] == nil || d["usage"].(map[string]any)["input_tokens"] != 77.0 {
		t.Fatalf("finished data = %v", d)
	}
	assertFits(t, f, "agent.job.finished")
}

// A cancel landing after execute returned but before the executor left execs still gets its
// finished record, from the executor's way out.
func TestExecute_CancelAfterExecuteReturnedStillEmitsFinished(t *testing.T) {
	var st *store.Store
	var once sync.Once
	prev := testHookExecuted
	testHookExecuted = func(runID string) {
		once.Do(func() {
			// The row was left running (its final write lost); a cancel lands now.
			if err := st.UpdateState(runID, store.StateRunning, store.StateCancelled); err != nil {
				t.Error(err)
			}
		})
	}
	t.Cleanup(func() { testHookExecuted = prev })
	r := newRig(t, rigOptions{outbox: true})
	st = r.st
	r.cfg.Store = &losingDoneStore{Store: r.st}
	sch, err := New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.submit("run-1", defaultProfile)
	if err := sch.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if outboxEvents(t, r.st, "run-1")[EventJobFinished] == nil {
		t.Fatal("the late cancel's finished record was never emitted")
	}
}

// losingDoneStore loses the final running -> done write.
type losingDoneStore struct{ *store.Store }

func (l *losingDoneStore) UpdateState(runID string, from, to store.State) error {
	if to == store.StateDone {
		return errors.New("injected: the database is locked")
	}
	return l.Store.UpdateState(runID, from, to)
}

// The sweep emits a deferred finished record whose run has no live executor.
func TestTick_SweepsDeferredFinishedWithNoLiveExecutor(t *testing.T) {
	r := newRig(t, rigOptions{outbox: true})
	j := &store.Job{RunID: "run-1", AgentKey: defaultProfile, State: store.StateRunning, Priority: 50, CreatedAt: time.Now().UTC()}
	if err := r.st.CreateJob(j); err != nil {
		t.Fatal(err)
	}
	if err := r.st.UpdateState("run-1", store.StateRunning, store.StateCancelled); err != nil {
		t.Fatal(err)
	}
	if outboxEvents(t, r.st, "run-1")[EventJobFinished] != nil {
		t.Fatal("the record was not deferred")
	}
	r.tick()
	if outboxEvents(t, r.st, "run-1")[EventJobFinished] == nil {
		t.Fatal("the sweep did not emit it")
	}
}

// A crash between a cancel and the executor's last write: reconciliation at the next start emits
// the deferred record.
func TestCancelRunning_ReconcileEmitsADeferredFinishedAfterACrash(t *testing.T) {
	r := newRig(t, rigOptions{outbox: true})
	j := &store.Job{RunID: "run-1", AgentKey: defaultProfile, State: store.StateRunning, Priority: 50, CreatedAt: time.Now().UTC()}
	if err := r.st.CreateJob(j); err != nil {
		t.Fatal(err)
	}
	if err := r.st.UpdateState("run-1", store.StateRunning, store.StateCancelled); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.st.ReconcileOrphans(); err != nil {
		t.Fatal(err)
	}
	if outboxEvents(t, r.st, "run-1")[EventJobFinished] == nil {
		t.Fatal("reconciliation did not emit the deferred record")
	}
}

// orphanRig is a rig with a short orphan grace and a row in state from with no executor.
func orphanRig(t *testing.T, from store.State, grace time.Duration, outbox bool) *rig {
	r := newRig(t, rigOptions{outbox: outbox, tweak: func(c *Config) { c.OrphanGrace = grace }})
	j := &store.Job{RunID: "orphan", AgentKey: defaultProfile, State: from, Priority: 50, CreatedAt: time.Now().UTC()}
	if err := r.st.CreateJob(j); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rig) sweepTwice(gap time.Duration) {
	r.sch.sweepOrphanedRuns()
	time.Sleep(gap)
	r.sch.sweepOrphanedRuns()
}

// A running row with no executor for the grace is failed (class unknown, the orphan reason),
// with its terminal events.
func TestOrphanSweep_FailsRunningRowWithNoExecutor(t *testing.T) {
	r := orphanRig(t, store.StateRunning, 5*time.Millisecond, true)
	r.sweepTwice(10 * time.Millisecond)
	j := r.job("orphan")
	if j.State != store.StateFailed || j.FailureClass != store.FailureUnknown || !strings.Contains(j.LocalFailedReason, store.OrphanFailedReason) {
		t.Fatalf("orphan = %s %q %q", j.State, j.FailureClass, j.LocalFailedReason)
	}
	if evs := outboxEvents(t, r.st, "orphan"); evs[EventJobFailed] == nil || evs[EventJobFinished] == nil {
		t.Fatalf("events = %v", evs)
	}
	if c := r.sch.Counters(); c.Finished[store.StateFailed] != 1 {
		t.Errorf("counters = %+v", c)
	}
}

func TestOrphanSweep_AwaitingInference(t *testing.T) {
	r := orphanRig(t, store.StateAwaitingInference, 5*time.Millisecond, false)
	r.sweepTwice(10 * time.Millisecond)
	if j := r.job("orphan"); j.State != store.StateFailed {
		t.Fatalf("orphan = %s", j.State)
	}
}

// An admitted orphan goes back to queued; a row seen once, younger than the grace, or with a live
// executor is left alone.
func TestOrphanSweep_KeepsLiveAndRecentRows(t *testing.T) {
	r := orphanRig(t, store.StateAdmitted, time.Hour, false)
	r.sweepTwice(time.Millisecond)
	if j := r.job("orphan"); j.State != store.StateAdmitted {
		t.Fatalf("a recent orphan was settled: %s", j.State)
	}
	r2 := orphanRig(t, store.StateAdmitted, 5*time.Millisecond, false)
	r2.sweepTwice(10 * time.Millisecond)
	if j := r2.job("orphan"); j.State != store.StateQueued {
		t.Fatalf("admitted orphan = %s, want queued", j.State)
	}
	release := make(chan struct{})
	r3 := newRig(t, rigOptions{runner: runnertest.New(runnertest.Block(release, "ok", nil)), tweak: func(c *Config) { c.OrphanGrace = time.Millisecond }})
	r3.submit("live", defaultProfile)
	done := r3.tickAsync(context.Background())
	r3.waitState("live", store.StateRunning)
	r3.sweepTwice(5 * time.Millisecond)
	if j := r3.job("live"); j.State != store.StateRunning {
		t.Fatalf("a live run was settled: %s", j.State)
	}
	close(release)
	waitClosed(t, done, "the live run")
}

func TestOrphanSweep_NegativeGraceDisables(t *testing.T) {
	r := orphanRig(t, store.StateRunning, -1, false)
	r.sweepTwice(5 * time.Millisecond)
	if j := r.job("orphan"); j.State != store.StateRunning {
		t.Fatalf("a disabled sweep settled: %s", j.State)
	}
}

// failingOrphanStore fails FailOrphan until told otherwise.
type failingOrphanStore struct {
	*store.Store
	fail  atomic.Bool
	calls atomic.Int32
}

func (f *failingOrphanStore) FailOrphan(runID string, from store.State, reason string) error {
	f.calls.Add(1)
	if f.fail.Load() {
		return errors.New("injected: disk full")
	}
	return f.Store.FailOrphan(runID, from, reason)
}

// A settle that fails is retried every sweep without a fresh grace, logged once per interval.
func TestOrphanSweep_FailedSettleRetriesWithoutNewGraceAndLogsOnce(t *testing.T) {
	r := orphanRig(t, store.StateRunning, 20*time.Millisecond, false)
	fs := &failingOrphanStore{Store: r.st}
	fs.fail.Store(true)
	r.cfg.Store = fs
	sch, err := New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	sch.sweepOrphanedRuns()
	time.Sleep(25 * time.Millisecond)
	for i := 0; i < 4; i++ {
		sch.sweepOrphanedRuns()
	}
	if fs.calls.Load() != 4 {
		t.Fatalf("FailOrphan called %d times, want every sweep past the grace (4)", fs.calls.Load())
	}
	logged := 0
	for _, l := range r.log.all() {
		if strings.Contains(l, "cannot settle") {
			logged++
		}
	}
	if logged != 1 {
		t.Errorf("logged %d times, want once", logged)
	}
	fs.fail.Store(false)
	sch.sweepOrphanedRuns()
	if j := r.job("orphan"); j.State != store.StateFailed {
		t.Fatalf("orphan = %s once the store recovered", j.State)
	}
}

// Many overlapping Ticks admit one queued run once: one session, one claim.
func TestConcurrentTicksAdmitARunOnce(t *testing.T) {
	release := make(chan struct{})
	run := runnertest.New(runnertest.Block(release, "ok", nil))
	r := newRig(t, rigOptions{runner: run, concur: 8})
	r.submit("run-1", defaultProfile)
	var dones []<-chan struct{}
	for i := 0; i < 8; i++ {
		dones = append(dones, r.tickAsync(context.Background()))
	}
	r.waitState("run-1", store.StateRunning)
	time.Sleep(20 * time.Millisecond)
	close(release)
	for _, d := range dones {
		waitClosed(t, d, "a tick")
	}
	if n := len(run.Sessions()); n != 1 {
		t.Fatalf("%d sessions for one run", n)
	}
	r.pool.balanced(t)
}

// A run requeued by a drain and admitted again while its first executor is still on its way out
// keeps the new executor's entry: a cancel then reaches the live session.
func TestReadmittedRunKeepsItsCancelFunc(t *testing.T) {
	var policy *backends.Policy
	var n atomic.Int32
	killed, second := make(chan struct{}), make(chan struct{})
	run := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		if n.Add(1) == 1 {
			if _, err := policy.SetDrained("engine-a", true); err != nil {
				return nil, err
			}
			return &runner.Result{}, runner.Wrap(runner.TurnFailed, errors.New("first"))
		}
		close(second)
		<-ctx.Done()
		close(killed)
		return &runner.Result{}, runner.Wrap(runner.KilledByController, ctx.Err())
	})
	r := newRig(t, rigOptions{runner: run, concur: 2, profiles: profileWith("max_attempts: 2\n")})
	policy = r.policy
	inHook := make(chan struct{})
	leave := make(chan struct{})
	var once sync.Once
	prev := testHookExecuted
	testHookExecuted = func(string) {
		once.Do(func() {
			close(inHook)
			<-leave
		})
	}
	t.Cleanup(func() { testHookExecuted = prev })
	r.submit("run-1", defaultProfile)
	first := r.tickAsync(context.Background())
	waitClosed(t, inHook, "the first executor's return")
	if j := r.job("run-1"); j.State != store.StateQueued {
		t.Fatalf("run-1 is %s, want requeued by the drain", j.State)
	}
	if _, err := policy.SetDrained("engine-a", false); err != nil {
		t.Fatal(err)
	}
	secondTick := r.tickAsync(context.Background())
	waitClosed(t, second, "the re-admitted session's start")
	close(leave)
	waitClosed(t, first, "the first tick")
	if !r.cancel("run-1") {
		t.Fatal("the re-admitted run's executor was lost")
	}
	waitClosed(t, killed, "the re-admitted session's kill")
	waitClosed(t, secondTick, "the second tick")
	r.pool.balanced(t)
}

// The holds: capacity is held only by live work. A run's claim is given back on success, a
// failure, a cancel, a kill and the job's deadline, and a restart starts with none (the pool's
// claims live in memory; ReconcileOrphans settles the rows), so the next job is admitted onto the
// single-slot backend each time.
func TestHolds_CapacityIsReleasedOnEveryEnd(t *testing.T) {
	oneSlot := []backends.Backend{{Name: "engine-a", MaxConcurrent: 1}}
	next := func(t *testing.T, r *rig) {
		t.Helper()
		if r.policy.HoldsReservation("run-1") {
			t.Fatal("run-1 still holds its claim")
		}
		r.submit("run-next", defaultProfile)
		r.tick()
		if j := r.job("run-next"); j.State != store.StateDone {
			t.Fatalf("the next job is %s: the slot was not given back", j.State)
		}
		r.pool.balanced(t)
	}
	t.Run("success and failure", func(t *testing.T) {
		r := newRig(t, rigOptions{runner: runnertest.New(runnertest.Fail(runner.TurnFailed, "x"), runnertest.Answer("ok")), backends: oneSlot})
		r.submit("run-1", defaultProfile)
		r.tick()
		next(t, r)
	})
	// run-1 blocks until its context ends; every other run answers (whether or not run-1's session
	// started before its cancel or deadline).
	blockFirst := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		if s.RunID == "run-1" {
			return runnertest.Block(make(chan struct{}), "", nil)(ctx, s)
		}
		return &runner.Result{Response: "ok"}, nil
	})
	t.Run("cancel", func(t *testing.T) {
		r := newRig(t, rigOptions{runner: blockFirst, backends: oneSlot})
		r.submit("run-1", defaultProfile)
		done := r.tickAsync(context.Background())
		r.waitState("run-1", store.StateRunning)
		r.cancel("run-1")
		waitClosed(t, done, "the cancelled run")
		next(t, r)
	})
	t.Run("deadline", func(t *testing.T) {
		r := newRig(t, rigOptions{runner: blockFirst, backends: oneSlot, jobLimit: 30 * time.Millisecond})
		r.submit("run-1", defaultProfile)
		r.tick()
		if j := r.job("run-1"); j.FailureClass != store.FailureDeadline {
			t.Fatalf("class %q", j.FailureClass)
		}
		next(t, r)
	})
	t.Run("kill", func(t *testing.T) {
		pr := &procRunner{mode: "hang", dir: t.TempDir()}
		var killNext atomic.Bool
		run := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
			if killNext.Load() {
				return &runner.Result{Response: "ok"}, nil
			}
			return pr.Run(ctx, s)
		})
		r := newRig(t, rigOptions{runner: run, backends: oneSlot})
		r.submit("run-1", defaultProfile)
		done := r.tickAsync(context.Background())
		pid, child := pr.sessionPids(t, "run-1", 0)
		killNext.Store(true)
		if err := killProcess(pid); err != nil {
			t.Fatal(err)
		}
		waitClosed(t, done, "the killed run")
		waitGone(t, pid, child)
		// The kill's automatic retry is queued too: let it run, then the next job.
		r.tick()
		next(t, r)
	})
	t.Run("shutdown", func(t *testing.T) {
		r := newRig(t, rigOptions{runner: blockFirst, backends: oneSlot})
		r.submit("run-1", defaultProfile)
		ctx, cancel := context.WithCancel(context.Background())
		done := r.tickAsync(ctx)
		r.waitState("run-1", store.StateRunning)
		cancel()
		waitClosed(t, done, "the shut-down run")
		j := r.job("run-1")
		if r.policy.HoldsReservation("run-1") || j.RetriedByRunID == "" {
			t.Fatalf("after the shutdown: claim held %v, retry %q", r.policy.HoldsReservation("run-1"), j.RetriedByRunID)
		}
		r.tick() // the retry takes the slot the shutdown gave back
		if retry := r.job(j.RetriedByRunID); retry.State != store.StateDone {
			t.Fatalf("the retry is %s: the slot was not given back", retry.State)
		}
		r.pool.balanced(t)
	})
	t.Run("exclusive lease", func(t *testing.T) {
		r := newRig(t, rigOptions{runner: blockFirst, backends: []backends.Backend{{Name: "engine-a"}}, concur: 2,
			profiles: map[string]string{defaultProfile: "", "solo": "backend_affinity: {exclusive: true}\n"}})
		r.submit("run-1", "solo")
		done := r.tickAsync(context.Background())
		r.waitState("run-1", store.StateRunning)
		r.submit("run-wait", defaultProfile)
		r.tick()
		if j := r.job("run-wait"); j.State != store.StateQueued {
			t.Fatalf("a job was admitted beside an exclusive lease: %s", j.State)
		}
		r.cancel("run-1")
		waitClosed(t, done, "the leased run")
		next(t, r)
		if j := r.job("run-wait"); j.State != store.StateDone {
			t.Fatalf("the waiting job is %s", j.State)
		}
	})
	t.Run("token weight", func(t *testing.T) {
		eng := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "engine:requests_running 0\nengine:cache_usage 0\nengine:cache_info{pool_tokens=\"100000\"} 1\n")
		}))
		t.Cleanup(eng.Close)
		r := newRig(t, rigOptions{runner: blockFirst, concur: 2, backends: []backends.Backend{{Name: "engine-a", LoadProbeURLs: []string{eng.URL}}},
			pool: func(p *backends.Policy) {
				p.LoadMetrics = []string{"engine:requests_running"}
				p.KV = backends.KVMetrics{Info: "engine:cache_info", PoolLabel: "pool_tokens", Usage: "engine:cache_usage"}
				p.TokenWeightedAdmission = true
			}})
		r.submit("run-1", defaultProfile)
		done := r.tickAsync(context.Background())
		r.waitState("run-1", store.StateRunning)
		r.submit("run-wait", defaultProfile)
		r.tick()
		if j := r.job("run-wait"); j.State != store.StateQueued {
			t.Fatalf("a second job fit a one-job token budget: %s", j.State)
		}
		r.cancel("run-1")
		waitClosed(t, done, "the weighted run")
		if r.policy.HoldsReservation("run-1") {
			t.Fatal("run-1 still holds its claim and weight")
		}
		r.tick()
		if j := r.job("run-wait"); j.State != store.StateDone {
			t.Fatalf("the waiting job is %s", j.State)
		}
		r.pool.balanced(t)
		if cs, _ := r.st.GetCallSizing("run-wait"); cs.WaitCause != backends.CauseTokenBudget {
			t.Errorf("wait cause = %q", cs.WaitCause)
		}
	})
	t.Run("restart", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "orch.db")
		st, err := store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		for id, s := range map[string]store.State{"run-admitted": store.StateAdmitted, "run-running": store.StateRunning} {
			if err := st.CreateJob(&store.Job{RunID: id, AgentKey: defaultProfile, State: s, Priority: 50, CreatedAt: time.Now().UTC(), TaskDescription: "t"}); err != nil {
				t.Fatal(err)
			}
		}
		st.Close() // the controller died with both in flight
		st, err = store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if requeued, failed, err := st.ReconcileOrphans(); err != nil || requeued != 1 || failed != 1 {
			t.Fatalf("ReconcileOrphans = %d, %d, %v", requeued, failed, err)
		}
		r := newRig(t, rigOptions{backends: oneSlot})
		r.cfg.Store = st
		r.st = st
		if r.sch, err = New(r.cfg); err != nil {
			t.Fatal(err)
		}
		r.tick()
		if j := r.job("run-admitted"); j.State != store.StateDone {
			t.Fatalf("the requeued run is %s after the restart", j.State)
		}
		if j := r.job("run-running"); j.State != store.StateFailed || j.LocalFailedReason != store.ReconcileFailedReason {
			t.Fatalf("the running row is %s %q", j.State, j.LocalFailedReason)
		}
		r.pool.balanced(t)
	})
}
