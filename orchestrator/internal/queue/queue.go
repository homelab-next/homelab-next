// SPDX-License-Identifier: Apache-2.0

// Package queue is the controller's run queue: it admits queued jobs in priority and aging order,
// up to a concurrency limit, through the backend pool (package backends), and runs each admitted
// job's attempt chain to a terminal state, recording what happened in the store.
//
// The queue decides from typed values only: the pool's sentinel errors (errors.Is), the runner
// classes a Call's Result carries (LocalClass, CloudClass, Attempts), and the store's states. It
// never decides on an error's text or a session's output (TestTheQueueReadsNoErrorText), and the
// reason it stores is the pool's bounded LocalFailedReason behind a class prefix, never the text
// of an error, which can quote a session's output.
//
// Capacity is held only by live work. A run's backend reservation is taken once per admission
// decision, by the one goroutine that admits, and released exactly once when its executor
// returns, however it returns: success, failure, a cancel, the job's deadline, a kill. A restart
// releases everything (the pool's reservations live in memory) and store.ReconcileOrphans settles
// the rows a crash left in flight.
package queue

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/backends"
	"github.com/homelab-next/homelab-next/orchestrator/internal/grants"
	"github.com/homelab-next/homelab-next/orchestrator/internal/inference"
	"github.com/homelab-next/homelab-next/orchestrator/internal/lessons"
	"github.com/homelab-next/homelab-next/orchestrator/internal/profile"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// Store is what the scheduler needs of the store; *store.Store implements it. It is an interface
// so a test can wrap the real store and fail one call deterministically.
type Store interface {
	ListByState(state store.State) ([]*store.Job, error)
	GetJob(runID string) (*store.Job, error)
	CreateJob(j *store.Job) error
	UpdateState(runID string, from, to store.State) error
	UpdateStateClass(runID string, from, to store.State, class string) error
	FailWithRetry(runID string, from store.State, class string, retry *store.Job) (retried bool, retryErr, err error)
	FailOrphan(runID string, from store.State, reason string) error
	UpdateExecutionResult(runID string, usedCloud bool, localAttempts int, localFailedReason, responseBody string) error
	UpdateTelemetry(runID, localBackendUsed string, c store.TokenCounts) error
	UpdateUsageFields(runID string, u store.UsageFields) error
	UpdateCallSizing(runID string, c store.CallSizing) error
	UpdatePromptProvenance(runID string, lessonIDs, runbookIDs []string, promptSHA256 string, promptBytes int) error
	UpdateProfileRevision(runID, revision string) error
	UpdateAttempts(runID string, attempts int) error
	EmitDeferredFinished(runID string) error
	DeferredFinishedPending() ([]string, error)
}

var _ Store = (*store.Store)(nil)

// Config is a scheduler's dependencies and settings, fixed at New.
type Config struct {
	// Store is the job store (required).
	Store Store
	// Pool admits and runs every job (required): backends.Policy, or a stub in a test.
	Pool backends.Pool
	// Profiles is the profile registry at start; SetProfiles replaces it. A job whose agent key
	// resolves to no profile fails (the API refuses an unknown agent key before it is queued; a
	// reload can still remove one).
	Profiles *profile.Registry
	// Lessons is the registers index the prompt's dispatch context is matched from; nil = none.
	Lessons *lessons.Index
	// Contracts are the contracts every prompt carries: nil is prompt.DefaultContracts(), an
	// empty, non-nil slice none (config.Config.PromptContractTexts gives the site's list, loaded
	// once at start).
	Contracts []string
	// Grants is the MCP grants catalog. A profile with a grants block needs it: such a job fails
	// when it is nil. A profile with no grants block runs with the runner's own server set.
	Grants *grants.Catalog
	// Concurrency bounds the jobs running at once (at least 1).
	Concurrency int
	// UsageDir receives each session's usage report (<run id>.json, then .aN for a later
	// attempt and .legN for a later leg, summed per run); empty: no usage report is asked for.
	UsageDir string
	// TreeRoot, when set, turns on the findings check: a job that ends cleanly but wrote nothing
	// under its profile's findings prefix for its lane fails (handler-error).
	TreeRoot string
	// GatewayTagPrefix prefixes the run id in the gateway tag (events.gateway_tag_prefix). The
	// outbox's event builder must be given the same prefix (OutboxEventBuilder).
	GatewayTagPrefix string
	// OrphanGrace is how long an in-flight row may have no live executor before the orphan sweep
	// settles it: 0 is DefaultOrphanGrace, negative disables the sweep.
	OrphanGrace time.Duration
	// Log receives the scheduler's log lines; nil is log.Printf.
	Log func(format string, args ...any)
}

// ErrInvalidConfig is wrapped by New.
var ErrInvalidConfig = errors.New("queue: invalid configuration")

// Scheduler is the run queue.
type Scheduler struct {
	cfg      Config
	profiles atomic.Pointer[profile.Registry]

	// admitMu is held by the one pass that is admitting: passes overlap (Run starts one per
	// interval, and a pass waits for its jobs), so a second pass that finds it held skips its
	// admission instead of reading a free-slot count the first is about to spend.
	admitMu sync.Mutex

	mu      sync.Mutex
	running int
	// requeues counts, by run id, how often a job went back to the queue because every backend
	// it may use was down (requeueBackendDown); in memory, so a restart resets it.
	requeues map[string]int
	// execs holds each live executor's entry, by run id, from admission until its executor has
	// returned. An executor removes only its own entry (identity, not run id): a run requeued by a
	// drain keeps its run id, and a concurrent Tick can admit it again before the old executor's
	// cleanup runs.
	execs map[string]*runExec
	// waitCauses: run id -> why it was last left queued (slot, token_budget, exclusive,
	// backend_down), written to the row when it finishes.
	waitCauses map[string]string
	// orphanSince and orphanErrLogged are the orphan sweep's state (orphan.go).
	orphanSince     map[string]time.Time
	orphanErrLogged map[string]time.Time

	counters counters
}

// runExec is one executor's entry in execs; its address identifies the executor.
type runExec struct {
	cancel context.CancelFunc
}

// New checks cfg and returns its scheduler.
func New(cfg Config) (*Scheduler, error) {
	switch {
	case cfg.Store == nil:
		return nil, fmt.Errorf("%w: no store", ErrInvalidConfig)
	case cfg.Pool == nil:
		return nil, fmt.Errorf("%w: no backend pool", ErrInvalidConfig)
	case cfg.Concurrency < 1:
		return nil, fmt.Errorf("%w: concurrency %d: want at least 1", ErrInvalidConfig, cfg.Concurrency)
	}
	if err := inference.ValidateGatewayTagPrefix(cfg.GatewayTagPrefix); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	cfg.Contracts = cloneContracts(cfg.Contracts)
	sch := &Scheduler{cfg: cfg, execs: map[string]*runExec{}}
	sch.profiles.Store(cfg.Profiles)
	return sch, nil
}

// cloneContracts copies c, keeping nil apart from empty.
func cloneContracts(c []string) []string {
	if c == nil {
		return nil
	}
	return append([]string{}, c...)
}

func (sch *Scheduler) logf(format string, args ...any) {
	if sch.cfg.Log != nil {
		sch.cfg.Log(format, args...)
		return
	}
	log.Printf(format, args...)
}

// SetProfiles swaps in a freshly loaded registry. A registry is never changed once loaded, so an
// executor sees the old one or the new one whole. nil leaves no profile: every job then fails.
func (sch *Scheduler) SetProfiles(reg *profile.Registry) { sch.profiles.Store(reg) }

// resolve is the job's profile in the current registry.
func (sch *Scheduler) resolve(agentKey string) (*profile.Profile, error) {
	reg := sch.profiles.Load()
	if reg == nil {
		return nil, profile.ErrProfileNotFound
	}
	return reg.Resolve(agentKey)
}

// HasProfile reports whether agentKey resolves to a profile: the API's check that refuses an
// unknown agent key (404) before anything is stored.
func (sch *Scheduler) HasProfile(agentKey string) bool {
	_, err := sch.resolve(agentKey)
	return err == nil
}

// CancelRun cancels the context of runID's live executor, which stops its session (the runner
// stops the whole process tree before Run returns). It reports whether one was live; a run with
// none (queued, finished) is no error: the API's cancel has already moved the row.
func (sch *Scheduler) CancelRun(runID string) bool {
	sch.mu.Lock()
	e, ok := sch.execs[runID]
	sch.mu.Unlock()
	if ok {
		e.cancel()
	}
	return ok
}

// BackendEligibilityEntry is one profile's verdict on one backend.
type BackendEligibilityEntry struct {
	AgentKey string `json:"agent_key"`
	Eligible bool   `json:"eligible"`
	Reason   string `json:"reason,omitempty"`
}

// ErrBackendNotConfigured: no configured backend has the name asked about.
var ErrBackendNotConfigured = errors.New("no configured backend has that name")

// BackendEligibility says, for every loaded profile, whether its affinity admits backend and why
// not, sorted by agent key.
func (sch *Scheduler) BackendEligibility(backend string) ([]BackendEligibilityEntry, error) {
	reg := sch.profiles.Load()
	if reg == nil {
		return nil, ErrBackendNotConfigured
	}
	var out []BackendEligibilityEntry
	found := false
	for _, p := range reg.All() {
		f, ok, reason := sch.cfg.Pool.ExplainEligibility(backend, backends.AffinityOf(p.BackendAffinity))
		if !f {
			continue
		}
		found = true
		out = append(out, BackendEligibilityEntry{AgentKey: p.AgentKey, Eligible: ok, Reason: reason})
	}
	if !found {
		// With no profile loaded the name cannot be checked through one: an empty affinity asks.
		if f, _, _ := sch.cfg.Pool.ExplainEligibility(backend, backends.Affinity{}); !f {
			return nil, ErrBackendNotConfigured
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentKey < out[j].AgentKey })
	return out, nil
}

// testHookExecuted, when set, runs after a job's execute returns and before its executor leaves
// execs (the window a late cancel defers its finished record into). Tests only.
var testHookExecuted func(runID string)

// Tick runs one admission pass: the sweeps, then as many queued jobs as there are free slots,
// each executed in its own goroutine. It returns once every job it admitted has finished, on
// every path, the admission error's included. Run starts each Tick in its own goroutine, so a long
// job never holds up admission; only one pass admits at a time (a pass that finds another
// admitting skips its admission), and every admission re-checks the free slots under the lock, so
// Concurrency is a hard cap on running jobs.
//
// The queued list is read once per pass and ordered once (by effective priority, then submit
// order): the cost of a pass is linear in the queue, however many jobs are held in it.
func (sch *Scheduler) Tick(ctx context.Context) error {
	sch.sweepDeferredFinished()
	sch.sweepOrphanedRuns()
	if !sch.admitMu.TryLock() {
		return nil
	}
	var wg sync.WaitGroup
	err := sch.admit(ctx, &wg)
	sch.admitMu.Unlock()
	wg.Wait()
	return err
}

// free is how many more jobs may start now.
func (sch *Scheduler) free() int {
	sch.mu.Lock()
	defer sch.mu.Unlock()
	return sch.cfg.Concurrency - sch.running
}

// heldKey is what makes two queued jobs the same work: one submitter's same agent, task and lane.
type heldKey struct {
	agent, task, submitter string
	shadow                 bool
}

func keyOf(j *store.Job) heldKey {
	return heldKey{agent: j.AgentKey, task: j.TaskDescription, submitter: j.SubmittedBy, shadow: j.Shadow}
}

// admit is one pass's admission, under admitMu; each admitted job's goroutine is added to wg.
func (sch *Scheduler) admit(ctx context.Context, wg *sync.WaitGroup) error {
	if sch.free() <= 0 {
		return nil
	}
	sch.reapStaleReservations()
	queued, err := sch.cfg.Store.ListByState(store.StateQueued)
	if err != nil {
		return fmt.Errorf("list queued: %w", err)
	}
	sch.pruneWaitCauses(queued)
	now := time.Now().UTC()
	order := orderQueued(queued, now)
	// The newest queued job of each key, for superseding a held duplicate.
	newest := make(map[heldKey]time.Time, len(queued))
	for _, j := range queued {
		if k := keyOf(j); j.CreatedAt.After(newest[k]) {
			newest[k] = j.CreatedAt
		}
	}
	// A job left queued for capacity takes no slot: a job behind one full backend must not starve
	// another that has room. Each queued job is considered once.
	for _, job := range order {
		if sch.free() <= 0 {
			break
		}
		if !store.CanTransition(job.State, store.StateAdmitted) || sch.cfg.Pool.HoldsReservation(job.RunID) {
			continue
		}
		prof, perr := sch.resolve(job.AgentKey)
		reserved, ok := "", true
		if perr == nil {
			reserved, ok = sch.reserve(ctx, job, prof)
		}
		if !ok {
			if sch.heldForHealth(prof) && newest[keyOf(job)].After(job.CreatedAt) {
				sch.supersede(job)
				continue
			}
			sch.noteWaitCause(job.RunID, sch.waitCause(job, prof))
			continue
		}
		if err := sch.cfg.Store.UpdateState(job.RunID, job.State, store.StateAdmitted); err != nil {
			sch.release(reserved, job.RunID)
			return fmt.Errorf("admit %s: %w", job.RunID, err)
		}
		sch.counters.admit()
		jobCtx, cancel := context.WithCancel(ctx)
		entry := &runExec{cancel: cancel}
		sch.mu.Lock()
		sch.running++
		sch.execs[job.RunID] = entry
		sch.mu.Unlock()

		wg.Add(1)
		go func(j *store.Job, reserved string) {
			defer wg.Done()
			defer func() {
				sch.mu.Lock()
				sch.running--
				owned := sch.execs[j.RunID] == entry
				if owned {
					delete(sch.execs, j.RunID)
				}
				sch.mu.Unlock()
				cancel()
				// A cancel that found this run live left its finished record to this executor;
				// once out of execs no later cancel can, so emit any that is pending. A
				// re-admitted executor owns the run now and emits on its own way out.
				if owned {
					sch.emitDeferredFinished(j.RunID)
				}
			}()
			sch.execute(jobCtx, j, reserved)
			if testHookExecuted != nil {
				testHookExecuted(j.RunID)
			}
		}(job, reserved)
	}
	return nil
}

// orderQueued is the queue in admission order at now: lowest effective priority first, then
// submit order (seq). Effective priority depends only on now within a pass, so one sort is it.
func orderQueued(queued []*store.Job, now time.Time) []*store.Job {
	type ranked struct {
		job *store.Job
		eff int
	}
	r := make([]ranked, len(queued))
	for i, j := range queued {
		r[i] = ranked{j, EffectivePriority(j.Priority, now.Sub(j.CreatedAt).Seconds())}
	}
	sort.Slice(r, func(a, b int) bool {
		if r[a].eff != r[b].eff {
			return r[a].eff < r[b].eff
		}
		return r[a].job.Seq < r[b].job.Seq
	})
	out := make([]*store.Job, len(r))
	for i := range r {
		out[i] = r[i].job
	}
	return out
}

// Run calls Tick every interval, each in its own goroutine, until ctx ends, and returns once every
// Tick (and so every job it admitted) has returned: the caller may close the store then.
func (sch *Scheduler) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var ticks sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			ticks.Wait()
			return
		case <-ticker.C:
			ticks.Add(1)
			go func() {
				defer ticks.Done()
				if err := sch.Tick(ctx); err != nil {
					sch.logf("queue: tick: %v", err)
				}
			}()
		}
	}
}

// reserve is the admission decision for one queued job: the backend reserved for it, or ok
// false to leave it queued. An exclusive job drains a backend and leases it once empty (called
// once per pass while queued); any other reserves a slot. When nothing it may use is up, a
// local-only job waits; any other job is admitted unreserved, and its chain runs only its cloud
// leg (the down backends are skipped, and a local attempt on a backend that came back meanwhile
// still takes a free slot at its max_concurrent or is skipped: backends.Policy.Call).
func (sch *Scheduler) reserve(ctx context.Context, job *store.Job, prof *profile.Profile) (string, bool) {
	affinity := backends.AffinityOf(prof.BackendAffinity)
	var backend string
	var ok bool
	if affinity.Exclusive {
		backend, ok = sch.cfg.Pool.ReserveExclusive(ctx, affinity, job.RunID)
	} else {
		backend, ok = sch.cfg.Pool.Reserve(ctx, affinity, job.RunID, job.AgentKey)
	}
	if ok {
		return backend, true
	}
	return "", !prof.LocalOnly && !sch.cfg.Pool.AnyHealthy(affinity)
}

// release returns runID's claim on backend; "" holds none.
func (sch *Scheduler) release(backend, runID string) {
	if backend != "" {
		sch.cfg.Pool.Release(backend, runID)
	}
}

// waitCause says why reserve just left job queued.
func (sch *Scheduler) waitCause(job *store.Job, prof *profile.Profile) string {
	if prof == nil {
		return ""
	}
	affinity := backends.AffinityOf(prof.BackendAffinity)
	switch {
	case affinity.Exclusive:
		return "exclusive"
	case !sch.cfg.Pool.AnyHealthy(affinity):
		return "backend_down"
	}
	return sch.cfg.Pool.LastRefusalCause(job.RunID)
}

// noteWaitCause remembers why runID was left queued (the last cause wins); takeWaitCause hands it
// to the row when the run finishes. In memory only: a restart loses it (the column stays NULL).
func (sch *Scheduler) noteWaitCause(runID, cause string) {
	if cause == "" {
		return
	}
	sch.mu.Lock()
	defer sch.mu.Unlock()
	if sch.waitCauses == nil {
		sch.waitCauses = map[string]string{}
	}
	sch.waitCauses[runID] = cause
}

func (sch *Scheduler) takeWaitCause(runID string) string {
	sch.mu.Lock()
	defer sch.mu.Unlock()
	c := sch.waitCauses[runID]
	delete(sch.waitCauses, runID)
	return c
}

// pruneWaitCauses drops the causes, and the backend-down requeue counts, of runs that are neither
// queued nor live (cancelled while queued, say), so neither map outgrows the queue.
func (sch *Scheduler) pruneWaitCauses(queued []*store.Job) {
	keep := make(map[string]bool, len(queued))
	for _, j := range queued {
		keep[j.RunID] = true
	}
	sch.mu.Lock()
	defer sch.mu.Unlock()
	for id := range sch.waitCauses {
		if _, live := sch.execs[id]; !live && !keep[id] {
			delete(sch.waitCauses, id)
		}
	}
	for id := range sch.requeues {
		if _, live := sch.execs[id]; !live && !keep[id] {
			delete(sch.requeues, id)
		}
	}
}

// heldForHealth reports whether a job of prof is held only because nothing it may use is up: a
// local-only profile during an outage.
func (sch *Scheduler) heldForHealth(prof *profile.Profile) bool {
	return prof != nil && prof.LocalOnly && !sch.cfg.Pool.AnyHealthy(backends.AffinityOf(prof.BackendAffinity))
}

// supersede cancels a local-only job held for a healthy backend when a newer queued job of the
// same submitter, agent, task and lane exists: an agent that keeps submitting on a timer during an
// outage would otherwise leave a stampede of identical runs for the backend's return. The newest
// run is the one worth doing; another submitter's job is never touched.
func (sch *Scheduler) supersede(job *store.Job) {
	if err := sch.cfg.Store.UpdateState(job.RunID, store.StateQueued, store.StateCancelled); err != nil {
		return
	}
	sch.takeWaitCause(job.RunID)
	sch.logf("queue: run=%s agent=%s held for a healthy backend, superseded by a newer identical run: cancelled", job.RunID, job.AgentKey)
}

// Counters are the scheduler's totals since it started (GET /metrics); a restart resets them, as
// it does a Prometheus counter.
type Counters struct {
	Admitted uint64
	// Finished counts the runs that reached each terminal state.
	Finished map[store.State]uint64
	// Attempts sums the attempt-chain runs of the finished jobs; Attempts minus the sum of
	// Finished is the retries.
	Attempts uint64
}

type counters struct {
	mu       sync.Mutex
	admitted uint64
	finished map[store.State]uint64
	attempts uint64
}

func (c *counters) admit() {
	c.mu.Lock()
	c.admitted++
	c.mu.Unlock()
}

func (c *counters) record(s store.State, attempts int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finished == nil {
		c.finished = map[store.State]uint64{}
	}
	c.finished[s]++
	c.attempts += uint64(max(attempts, 0))
}

// Counters returns a snapshot of the totals.
func (sch *Scheduler) Counters() Counters {
	c := &sch.counters
	c.mu.Lock()
	defer c.mu.Unlock()
	out := Counters{Admitted: c.admitted, Attempts: c.attempts, Finished: make(map[store.State]uint64, len(c.finished))}
	for k, v := range c.finished {
		out.Finished[k] = v
	}
	return out
}
