// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/backends"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner/runnertest"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// withUsage writes usage to the session's usage path, then runs then.
func withUsage(usage map[string]any, then runnertest.Step) runnertest.Step {
	return func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		if s.UsagePath != "" {
			b, _ := json.Marshal(usage)
			if err := os.WriteFile(s.UsagePath, b, 0o600); err != nil {
				return &runner.Result{}, err
			}
		}
		res, err := then(ctx, s)
		if res != nil {
			res.Usage = usage
		}
		return res, err
	}
}

func TestScheduler_New_RefusesAnIncompleteConfig(t *testing.T) {
	r := newRig(t, rigOptions{})
	for name, cfg := range map[string]Config{
		"no store":       {Pool: r.pool, Concurrency: 1},
		"no pool":        {Store: r.st, Concurrency: 1},
		"no concurrency": {Store: r.st, Pool: r.pool},
		"bad tag prefix": {Store: r.st, Pool: r.pool, Concurrency: 1, GatewayTagPrefix: "a,b"},
	} {
		if _, err := New(cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: New = %v, want ErrInvalidConfig", name, err)
		}
	}
}

// A queued job is admitted, its one session gets the run's identity, lane, toolsets, tag and
// prompt, the answer is stored, and its claim is released once.
func TestScheduler_AdmitsAndRunsAQueuedJobToDone(t *testing.T) {
	run := runnertest.New(runnertest.Answer("all services answered"))
	r := newRig(t, rigOptions{runner: run, tweak: func(c *Config) { c.Contracts = []string{"[contract] file one finding."} }})
	r.submit("run-1", defaultProfile)
	r.tick()
	j := r.job("run-1")
	if j.State != store.StateDone || j.ResponseBody != "all services answered" || j.Attempts != 1 || j.LocalBackendUsed != "engine-a" {
		t.Fatalf("job = %s %q attempts=%d backend=%q", j.State, j.ResponseBody, j.Attempts, j.LocalBackendUsed)
	}
	s := run.Sessions()
	if len(s) != 1 {
		t.Fatalf("%d sessions, want 1", len(s))
	}
	got := s[0]
	if got.RunID != "run-1" || got.AgentKey != defaultProfile || got.Lane != runner.LaneReal ||
		!reflect.DeepEqual(got.Toolsets, []string{"notes", "web"}) || got.GatewayTag != "hnx/run-1" || got.Servers != nil {
		t.Errorf("session = %+v", got)
	}
	if !strings.HasPrefix(got.Prompt, "check the watched services") || !strings.Contains(got.Prompt, "[contract] file one finding.") {
		t.Errorf("prompt = %q", got.Prompt)
	}
	if j.PromptSHA256 == "" || j.PromptBytes != len(got.Prompt) || j.ProfileRevision == "" {
		t.Errorf("provenance: sha=%q bytes=%d revision=%q", j.PromptSHA256, j.PromptBytes, j.ProfileRevision)
	}
	r.pool.balanced(t)
	if r.pool.claimCount() != 1 || r.pool.calls[0] != "engine-a" {
		t.Errorf("claims %d, Call got reserved %v", r.pool.claimCount(), r.pool.calls)
	}
	if c := r.sch.Counters(); c.Admitted != 1 || c.Finished[store.StateDone] != 1 || c.Attempts != 1 {
		t.Errorf("counters = %+v", c)
	}
}

// A shadow job runs on the shadow lane with the shadow toolsets.
func TestScheduler_ShadowJobUsesShadowToolsets(t *testing.T) {
	run := runnertest.New()
	r := newRig(t, rigOptions{runner: run})
	j := &store.Job{RunID: "run-s", AgentKey: defaultProfile, Priority: 50, State: store.StateQueued, Shadow: true,
		CreatedAt: time.Now().UTC(), TaskDescription: "t"}
	if err := r.st.CreateJob(j); err != nil {
		t.Fatal(err)
	}
	r.tick()
	if s := run.Sessions(); len(s) != 1 || s[0].Lane != runner.LaneShadow || !reflect.DeepEqual(s[0].Toolsets, []string{"notes"}) {
		t.Fatalf("sessions = %+v", s)
	}
}

// At most Concurrency jobs run at once; a freed slot admits the next.
func TestScheduler_RespectsConcurrencyLimit(t *testing.T) {
	release := make(chan struct{})
	run := runnertest.New(runnertest.Block(release, "done", nil))
	r := newRig(t, rigOptions{runner: run, concur: 1})
	r.submit("run-1", defaultProfile)
	r.submit("run-2", defaultProfile)
	first := r.tickAsync(context.Background())
	r.waitState("run-1", store.StateRunning)
	r.tick() // the slot is taken: nothing more is admitted
	if j := r.job("run-2"); j.State != store.StateQueued {
		t.Fatalf("run-2 is %s while the only slot is taken", j.State)
	}
	close(release)
	waitClosed(t, first, "the first tick")
	r.tick()
	r.waitState("run-2", store.StateDone)
	r.pool.balanced(t)
}

// A local failure the backend is to blame for falls back to the cloud leg; the run records the
// fallback and the local reason, class first.
func TestScheduler_ForcedLocalFailureFallsBackToCloudAndRecordsIt(t *testing.T) {
	run := runnertest.New(runnertest.On(map[string]runnertest.Step{
		"engine-a": runnertest.Fail(runner.BackendFault, "connection reset"),
		"cloud":    runnertest.Answer("cloud answer"),
	}, runnertest.Answer("?")))
	r := newRig(t, rigOptions{runner: run, cloud: "cloud-home"})
	r.submit("run-1", defaultProfile)
	r.tick()
	j := r.job("run-1")
	if j.State != store.StateDone || !j.CloudFallbackUsed || j.ResponseBody != "cloud answer" || j.LocalAttempts != 1 {
		t.Fatalf("job = %s cloud=%v response=%q local=%d", j.State, j.CloudFallbackUsed, j.ResponseBody, j.LocalAttempts)
	}
	if !strings.HasPrefix(j.LocalFailedReason, "backend-fault: ") {
		t.Errorf("local reason = %q, want the class first", j.LocalFailedReason)
	}
}

// When every leg fails the run is failed with its class, the class-prefixed reason and its
// attempt trail, and the last session's output is not stored as an answer.
func TestScheduler_TotalFailurePreservesAuditTrail(t *testing.T) {
	run := runnertest.New(func(context.Context, runner.Session) (*runner.Result, error) {
		return &runner.Result{Response: "partial transcript that is no answer", Usage: map[string]any{"input_tokens": float64(5)}},
			runner.Wrap(runner.TurnFailed, errors.New("the turn failed"))
	})
	r := newRig(t, rigOptions{runner: run, cloud: "cloud-home"})
	r.submit("run-1", defaultProfile)
	r.tick()
	j := r.job("run-1")
	if j.State != store.StateFailed || j.FailureClass != store.FailureHandlerError || !j.CloudFallbackUsed || j.LocalAttempts != 1 {
		t.Fatalf("job = %s class=%q cloud=%v local=%d", j.State, j.FailureClass, j.CloudFallbackUsed, j.LocalAttempts)
	}
	if j.ResponseBody != "" {
		t.Errorf("a failed run stored %q as its answer", j.ResponseBody)
	}
	if !strings.HasPrefix(j.LocalFailedReason, "handler-error: turn-failed: ") {
		t.Errorf("reason = %q", j.LocalFailedReason)
	}
	if j.InputTokens != 5 {
		t.Errorf("a failed run's usage was dropped: input tokens %d", j.InputTokens)
	}
	r.pool.balanced(t)
}

// failingAdmitStore fails the admission of one run id.
type failingAdmitStore struct {
	*store.Store
	failID string
}

func (f *failingAdmitStore) UpdateState(runID string, from, to store.State) error {
	if runID == f.failID && to == store.StateAdmitted {
		return errors.New("injected admission failure")
	}
	return f.Store.UpdateState(runID, from, to)
}

// An admission error mid-pass still waits for the jobs the pass already started, and the claim
// the failed admission took is given back.
func TestScheduler_TickWaitsForInFlightJobsEvenWhenAdmissionFails(t *testing.T) {
	release := make(chan struct{})
	run := runnertest.New(runnertest.Block(release, "done", nil))
	r := newRig(t, rigOptions{runner: run, concur: 2, backends: []backends.Backend{{Name: "engine-a"}, {Name: "engine-b"}}})
	r.submit("run-1", defaultProfile)
	time.Sleep(2 * time.Millisecond)
	r.submit("run-2", defaultProfile)
	cfg := r.cfg
	cfg.Store = &failingAdmitStore{Store: r.st, failID: "run-2"}
	sch, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- sch.Tick(context.Background()) }()
	r.waitState("run-1", store.StateRunning)
	select {
	case err := <-errc:
		t.Fatalf("Tick returned (%v) with a job still running", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-errc; err == nil || !strings.Contains(err.Error(), "injected admission failure") {
		t.Fatalf("Tick = %v, want the admission error", err)
	}
	if j := r.job("run-1"); j.State != store.StateDone {
		t.Fatalf("run-1 is %s", j.State)
	}
	r.pool.balanced(t)
}

// A job whose agent key no longer resolves (a reload removed its profile) fails with a
// class-prefixed reason and no session; so does every job when no registry is loaded.
func TestScheduler_UnresolvableProfileFailsTheJob(t *testing.T) {
	run := runnertest.New()
	r := newRig(t, rigOptions{runner: run})
	r.submit("run-1", "retired-agent")
	r.tick()
	j := r.job("run-1")
	if j.State != store.StateFailed || j.FailureClass != store.FailureHandlerError || !strings.HasPrefix(j.LocalFailedReason, "handler-error: no profile") {
		t.Fatalf("job = %s %q %q", j.State, j.FailureClass, j.LocalFailedReason)
	}
	r.sch.SetProfiles(nil)
	r.submit("run-2", defaultProfile)
	r.tick()
	if j := r.job("run-2"); j.State != store.StateFailed {
		t.Fatalf("with no registry run-2 is %s", j.State)
	}
	if len(run.Sessions()) != 0 {
		t.Fatal("a job without a profile started a session")
	}
	r.pool.balanced(t)
}

// A job with no task and no profile default fails before any session.
func TestScheduler_NoTaskFailsBeforeAnySession(t *testing.T) {
	run := runnertest.New()
	r := newRig(t, rigOptions{runner: run})
	j := &store.Job{RunID: "run-1", AgentKey: defaultProfile, Priority: 50, State: store.StateQueued, CreatedAt: time.Now().UTC()}
	if err := r.st.CreateJob(j); err != nil {
		t.Fatal(err)
	}
	r.tick()
	if got := r.job("run-1"); got.State != store.StateFailed || !strings.Contains(got.LocalFailedReason, "task_description") {
		t.Fatalf("job = %s %q", got.State, got.LocalFailedReason)
	}
	if len(run.Sessions()) != 0 {
		t.Fatal("a session started")
	}
}

// A run id the gateway tag refuses fails the job before any attempt: no session runs untagged.
func TestScheduler_InvalidRunIDFailsBeforeAnyAttempt(t *testing.T) {
	run := runnertest.New()
	r := newRig(t, rigOptions{runner: run})
	r.submit("run/1", defaultProfile)
	r.tick()
	if got := r.job("run/1"); got.State != store.StateFailed || !strings.Contains(got.LocalFailedReason, "gateway tag") {
		t.Fatalf("job = %s %q", got.State, got.LocalFailedReason)
	}
	if len(run.Sessions()) != 0 {
		t.Fatal("a session started for a run id the tag refuses")
	}
	r.pool.balanced(t)
}

// Run starts each Tick in its own goroutine, so a long job never holds up the admission of
// another.
func TestScheduler_RunAdmitsANewJobWhileAnEarlierOneIsStillExecuting(t *testing.T) {
	release := make(chan struct{})
	run := runnertest.New(runnertest.On(map[string]runnertest.Step{"engine-a": runnertest.Block(release, "slow", nil)}, runnertest.Answer("fast")))
	r := newRig(t, rigOptions{runner: run, concur: 2, backends: []backends.Backend{{Name: "engine-a", MaxConcurrent: 1}, {Name: "engine-b", MaxConcurrent: 1}},
		tweak: func(c *Config) {}})
	r.policy.PrimaryFirst = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.sch.Run(ctx, 20*time.Millisecond); close(done) }()
	r.submit("run-slow", defaultProfile)
	r.waitState("run-slow", store.StateRunning)
	r.submit("run-fast", defaultProfile)
	r.waitState("run-fast", store.StateDone)
	close(release)
	r.waitState("run-slow", store.StateDone)
	cancel()
	waitClosed(t, done, "Run's return")
	r.pool.balanced(t)
}

// HasProfile answers from the current registry.
func TestScheduler_HasProfile(t *testing.T) {
	r := newRig(t, rigOptions{})
	if !r.sch.HasProfile(defaultProfile) || r.sch.HasProfile("nobody") {
		t.Fatal("HasProfile wrong")
	}
	r.sch.SetProfiles(nil)
	if r.sch.HasProfile(defaultProfile) {
		t.Fatal("HasProfile true with no registry")
	}
}

// BackendEligibility says, per profile, whether its affinity admits the backend and why not; an
// unknown backend is ErrBackendNotConfigured.
func TestScheduler_BackendEligibilityExplainsRealExclusions(t *testing.T) {
	r := newRig(t, rigOptions{
		backends: []backends.Backend{{Name: "engine-a", Tags: []string{"gpu"}, MaxContext: 32000}, {Name: "engine-b", MaxContext: 8000}},
		profiles: map[string]string{
			"watcher":   "",
			"big-ctx":   "backend_affinity: {min_context: 16000}\n",
			"gpu-only":  "backend_affinity: {require_tags: [gpu]}\n",
			"no-engine": "backend_affinity: {exclude_backends: [engine-b]}\n",
		},
	})
	got, err := r.sch.BackendEligibility("engine-b")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"big-ctx": false, "gpu-only": false, "no-engine": false, "watcher": true}
	if len(got) != len(want) {
		t.Fatalf("entries = %+v", got)
	}
	for i, e := range got {
		if i > 0 && got[i-1].AgentKey > e.AgentKey {
			t.Errorf("not sorted: %+v", got)
		}
		if want[e.AgentKey] != e.Eligible || (!e.Eligible && e.Reason == "") {
			t.Errorf("%+v", e)
		}
	}
	if _, err := r.sch.BackendEligibility("engine-z"); !errors.Is(err, ErrBackendNotConfigured) {
		t.Fatalf("unknown backend = %v", err)
	}
}

// A job blocked on a full backend stays queued and takes no slot of the pass: another job whose
// backend has room is admitted in the same pass; once room frees up the first runs. The wait
// cause is recorded on its row.
func TestScheduler_TickHoldsCapacityBlockedJobQueuedButAdmitsADifferentAdmittableOne(t *testing.T) {
	release := make(chan struct{})
	run := runnertest.New(runnertest.On(map[string]runnertest.Step{"engine-a": runnertest.Block(release, "a", nil)}, runnertest.Answer("b")))
	r := newRig(t, rigOptions{runner: run, concur: 3,
		backends: []backends.Backend{{Name: "engine-a", Tags: []string{"a"}, MaxConcurrent: 1}, {Name: "engine-b", Tags: []string{"b"}, MaxConcurrent: 1}},
		profiles: map[string]string{"on-a": "backend_affinity: {require_tags: [a]}\n", "on-b": "backend_affinity: {require_tags: [b]}\n"}})
	r.submit("run-a1", "on-a")
	first := r.tickAsync(context.Background())
	r.waitState("run-a1", store.StateRunning)
	r.submit("run-a2", "on-a")
	time.Sleep(2 * time.Millisecond)
	r.submit("run-b", "on-b")
	r.tick()
	if j := r.job("run-a2"); j.State != store.StateQueued {
		t.Fatalf("run-a2 is %s with engine-a full", j.State)
	}
	if j := r.job("run-b"); j.State != store.StateDone {
		t.Fatalf("run-b is %s: the blocked job took its slot", j.State)
	}
	close(release)
	waitClosed(t, first, "the first tick")
	r.tick()
	r.waitState("run-a2", store.StateDone)
	if cs, err := r.st.GetCallSizing("run-a2"); err != nil || cs.WaitCause != backends.CauseSlot {
		t.Errorf("run-a2's wait cause = %+v, %v", cs, err)
	}
	r.pool.balanced(t)
}

// Two jobs submitted together for one single-slot backend: the pass reserves for the first, so
// the second is left queued in the same pass, never admitted onto a full backend.
func TestScheduler_TickReservationClosesSameTickBurstRace(t *testing.T) {
	release := make(chan struct{})
	run := runnertest.New(runnertest.Block(release, "done", nil))
	r := newRig(t, rigOptions{runner: run, concur: 4, backends: []backends.Backend{{Name: "engine-a", MaxConcurrent: 1}}})
	r.submit("run-1", defaultProfile)
	r.submit("run-2", defaultProfile)
	done := r.tickAsync(context.Background())
	r.waitState("run-1", store.StateRunning)
	time.Sleep(20 * time.Millisecond)
	if j := r.job("run-2"); j.State != store.StateQueued {
		t.Fatalf("run-2 is %s: admitted onto a full backend", j.State)
	}
	close(release)
	waitClosed(t, done, "the tick")
	r.pool.balanced(t)
}

// health is a backend's health endpoint whose answer the test switches.
type health struct {
	*httptest.Server
	ok atomic.Bool
}

func newHealth(t *testing.T) *health {
	h := &health{}
	h.ok.Store(true)
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !h.ok.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(h.Close)
	return h
}

func probe(r *rig) {
	for i := 0; i < 5; i++ {
		r.policy.ProbeOnce(context.Background())
	}
}

// A local-only job waits queued while every backend it may use is down (cause backend_down) and
// runs once one is up; a newer identical job supersedes a held one.
func TestScheduler_LocalOnlyJobWaitsQueuedWhileBackendDownThenRuns(t *testing.T) {
	h := newHealth(t)
	run := runnertest.New()
	r := newRig(t, rigOptions{runner: run, cloud: "cloud-home", backends: []backends.Backend{{Name: "engine-a", HealthURL: h.URL}},
		profiles: map[string]string{defaultProfile: "local_only: true\n"}})
	h.ok.Store(false)
	probe(r)
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.State != store.StateQueued {
		t.Fatalf("run-1 is %s with its only backend down", j.State)
	}
	time.Sleep(2 * time.Millisecond)
	r.submit("run-2", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.State != store.StateCancelled {
		t.Fatalf("the held run-1 is %s, want superseded by run-2", j.State)
	}
	h.ok.Store(true)
	probe(r)
	r.tick()
	j := r.waitState("run-2", store.StateDone)
	if j.CloudFallbackUsed {
		t.Fatal("a local-only job used the cloud")
	}
	if cs, _ := r.st.GetCallSizing("run-2"); cs.WaitCause != "backend_down" {
		t.Errorf("wait cause = %q", cs.WaitCause)
	}
	r.pool.balanced(t)
}

// A local-only job whose backend is found down by the call itself (the runner's absent hint,
// confirmed by the pool's probe) goes back to queued under its own run id, not failed, waits
// while the backend is down, and runs when it returns.
func TestScheduler_LocalOnlyJobWhoseBackendsAreAllDownIsRequeued(t *testing.T) {
	h := newHealth(t)
	var calls atomic.Int32
	run := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		if calls.Add(1) == 1 {
			h.ok.Store(false)
			return &runner.Result{}, runner.MarkAbsent(errors.New("connection refused"))
		}
		return &runner.Result{Response: "done"}, nil
	})
	r := newRig(t, rigOptions{runner: run, backends: []backends.Backend{{Name: "engine-a", HealthURL: h.URL}},
		profiles: map[string]string{defaultProfile: "local_only: true\n"}})
	r.submit("run-1", defaultProfile)
	r.tick()
	j := r.job("run-1")
	if j.State != store.StateQueued || j.Attempts != 1 {
		t.Fatalf("run-1 is %s (attempts %d), want back to queued", j.State, j.Attempts)
	}
	r.tick()
	if j := r.job("run-1"); j.State != store.StateQueued {
		t.Fatalf("run-1 is %s while its backend is down", j.State)
	}
	h.ok.Store(true)
	probe(r)
	r.tick()
	if j := r.waitState("run-1", store.StateDone); j.Attempts != 2 {
		t.Errorf("attempts = %d, want 2 under one run id", j.Attempts)
	}
	if q, _ := r.st.ListByState(store.StateQueued); len(q) != 0 {
		t.Errorf("a new run was queued: %v", q)
	}
	r.pool.balanced(t)
}

// Cancelling a running job kills its session's whole process tree before the executor returns,
// and gives its claim back.
func TestScheduler_CancelRunActuallyKillsTheRealSubprocess(t *testing.T) {
	pr := &procRunner{mode: "hang", dir: t.TempDir()}
	r := newRig(t, rigOptions{runner: pr})
	r.submit("run-1", defaultProfile)
	done := r.tickAsync(context.Background())
	pid, child := pr.sessionPids(t, "run-1", 0)
	if err := r.st.UpdateState("run-1", store.StateRunning, store.StateCancelled); err != nil {
		t.Fatal(err)
	}
	if !r.sch.CancelRun("run-1") {
		t.Fatal("CancelRun found no live executor")
	}
	waitClosed(t, done, "the cancelled job's executor")
	waitGone(t, pid, child)
	if j := r.job("run-1"); j.State != store.StateCancelled {
		t.Fatalf("run-1 is %s", j.State)
	}
	if r.sch.CancelRun("run-1") {
		t.Fatal("CancelRun found an executor after it returned")
	}
	if r.policy.HoldsReservation("run-1") {
		t.Fatal("the cancelled run still holds its claim")
	}
	r.pool.balanced(t)
}

// A real session's answer and its usage report reach the row.
func TestScheduler_RealSubprocessAnswerAndUsageAreStored(t *testing.T) {
	pr := &procRunner{mode: "answer", dir: t.TempDir()}
	r := newRig(t, rigOptions{runner: pr})
	r.submit("run-1", defaultProfile)
	r.tick()
	j := r.job("run-1")
	if j.State != store.StateDone || j.ResponseBody != "finding filed" || j.InputTokens != 10 || j.OutputTokens != 2 {
		t.Fatalf("job = %s %q in=%d out=%d", j.State, j.ResponseBody, j.InputTokens, j.OutputTokens)
	}
}

// The usage report of every session, read from the usage directory, is the run's telemetry.
func TestScheduler_TelemetryPersistedFromUsageFile(t *testing.T) {
	usage := map[string]any{"input_tokens": float64(1200), "output_tokens": float64(300), "reasoning_tokens": float64(40),
		"api_calls": float64(3), "session_id": "sess-9", "model": "model-a", "completed": true, "turn_exit_reason": "text_response(stop)",
		"cost_usd": 0.25}
	run := runnertest.New(withUsage(usage, runnertest.Answer("done")))
	r := newRig(t, rigOptions{runner: run, tweak: func(c *Config) { c.UsageDir = filepath.Join(t.TempDir(), "usage") }})
	r.submit("run-1", defaultProfile)
	r.tick()
	j := r.job("run-1")
	if j.InputTokens != 1200 || j.OutputTokens != 300 || j.ReasoningTokens != 40 || j.APICalls != 3 ||
		j.SessionID != "sess-9" || j.Model != "model-a" || j.Completed == nil || !*j.Completed || j.CostUSD != 0.25 {
		t.Fatalf("telemetry = %+v", j)
	}
	if s := run.Sessions(); s[0].UsagePath != filepath.Join(r.cfg.UsageDir, "run-1.json") {
		t.Errorf("usage path = %q", s[0].UsagePath)
	}
	fi, err := os.Stat(r.cfg.UsageDir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("usage directory = %v, %v; want owner-only", fi, err)
	}
}

// An answer longer than MaxResponseBytes is stored cut, with a marker.
func TestScheduler_AnswerIsBounded(t *testing.T) {
	long := strings.Repeat("é", MaxResponseBytes)
	r := newRig(t, rigOptions{runner: runnertest.New(runnertest.Answer(long))})
	r.submit("run-1", defaultProfile)
	r.tick()
	j := r.job("run-1")
	if len(j.ResponseBody) > MaxResponseBytes || !strings.HasSuffix(j.ResponseBody, truncatedMarker) {
		t.Fatalf("stored %d bytes, ends %q", len(j.ResponseBody), j.ResponseBody[len(j.ResponseBody)-40:])
	}
}

// The stored reason and the log carry the pool's bounded reason behind the class, never the whole
// text of the failure, which can quote a session.
func TestScheduler_ReasonIsBoundedAndNeverTheErrorText(t *testing.T) {
	tail := "TAIL-OF-THE-SESSION-OUTPUT"
	run := runnertest.New(runnertest.Fail(runner.TurnFailed, strings.Repeat("x", 2000)+tail))
	r := newRig(t, rigOptions{runner: run})
	r.submit("run-1", defaultProfile)
	r.tick()
	j := r.job("run-1")
	if strings.Contains(j.LocalFailedReason, tail) || len(j.LocalFailedReason) > 600 || !strings.HasPrefix(j.LocalFailedReason, "handler-error: ") {
		t.Fatalf("reason (%d bytes) = %.80q", len(j.LocalFailedReason), j.LocalFailedReason)
	}
	for _, l := range r.log.all() {
		if strings.Contains(l, tail) {
			t.Fatalf("the log quotes the failure's whole text: %.120q", l)
		}
	}
}
