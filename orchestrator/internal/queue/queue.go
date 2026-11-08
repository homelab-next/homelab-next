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

	mu      sync.Mutex
	running int
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
// job never holds up admission.
func (sch *Scheduler) Tick(ctx context.Context) error {
	sch.sweepDeferredFinished()
	sch.sweepOrphanedRuns()
	sch.mu.Lock()
	available := sch.cfg.Concurrency - sch.running
	sch.mu.Unlock()
	if available <= 0 {
		return nil
	}
	sch.reapStaleReservations()

	queued, err := sch.cfg.Store.ListByState(store.StateQueued)
	if err != nil {
		return fmt.Errorf("list queued: %w", err)
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	now := time.Now().UTC()
	admitted := 0
	// A job left queued for capacity takes none of this pass's slots: a job behind one full
	// backend must not starve another that has room. Each queued job is considered once.
	for admitted < available && len(queued) > 0 {
		job := PickNext(queued, now)
		queued = removeJob(queued, job.RunID)
		if !store.CanTransition(job.State, store.StateAdmitted) {
			continue
		}
		// Ticks overlap, so another may be admitting this run now and hold its claim; the pool
		// also refuses a second claim for one run id.
		if sch.cfg.Pool.HoldsReservation(job.RunID) {
			continue
		}
		prof, perr := sch.resolve(job.AgentKey)
		reserved, ok := "", true
		if perr == nil {
			reserved, ok = sch.reserve(ctx, job, prof)
		}
		if !ok {
			sch.noteWaitCause(job.RunID, sch.waitCause(job, prof))
			sch.supersedeIfHeldDuplicate(job, prof)
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
		admitted++

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

func removeJob(jobs []*store.Job, runID string) []*store.Job {
	out := jobs[:0]
	for _, j := range jobs {
		if j.RunID != runID {
			out = append(out, j)
		}
	}
	return out
}

// reserve is the admission decision for one queued job: the backend reserved for it, or ok
// false to leave it queued. A local-only job waits while nothing eligible is up; any other job is
// admitted unreserved then, and the pool skips the down backends and runs its cloud leg. An
// exclusive job drains a backend and leases it once empty (called once per pass while queued).
func (sch *Scheduler) reserve(ctx context.Context, job *store.Job, prof *profile.Profile) (string, bool) {
	affinity := backends.AffinityOf(prof.BackendAffinity)
	if !sch.cfg.Pool.AnyHealthy(affinity) {
		return "", !prof.LocalOnly
	}
	if affinity.Exclusive {
		return sch.cfg.Pool.ReserveExclusive(ctx, affinity, job.RunID)
	}
	return sch.cfg.Pool.Reserve(ctx, affinity, job.RunID, job.AgentKey)
}

// release returns runID's claim on backend; "" holds none.
func (sch *Scheduler) release(backend, runID string) {
	if backend != "" {
		sch.cfg.Pool.Release(backend, runID)
	}
}

// waitCause says why reserve just left job queued.
func (sch *Scheduler) waitCause(job *store.Job, prof *profile.Profile) string {
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

// supersedeIfHeldDuplicate cancels a local-only job held queued because nothing eligible is up
// when a newer queued job of the same agent and task exists: an agent that keeps submitting on a
// timer during an outage would otherwise leave a stampede of identical runs for the backend's
// return. The newest run is the one worth doing.
func (sch *Scheduler) supersedeIfHeldDuplicate(job *store.Job, prof *profile.Profile) {
	if prof == nil || !prof.LocalOnly || sch.cfg.Pool.AnyHealthy(backends.AffinityOf(prof.BackendAffinity)) {
		return
	}
	queued, err := sch.cfg.Store.ListByState(store.StateQueued)
	if err != nil {
		return
	}
	for _, other := range queued {
		if other.RunID != job.RunID && other.AgentKey == job.AgentKey &&
			other.TaskDescription == job.TaskDescription && other.CreatedAt.After(job.CreatedAt) {
			if err := sch.cfg.Store.UpdateState(job.RunID, store.StateQueued, store.StateCancelled); err == nil {
				sch.logf("queue: run=%s agent=%s held for a healthy backend, superseded by the newer run=%s: cancelled", job.RunID, job.AgentKey, other.RunID)
			}
			return
		}
	}
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
