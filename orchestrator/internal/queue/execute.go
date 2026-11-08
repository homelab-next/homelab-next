// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/backends"
	"github.com/homelab-next/homelab-next/orchestrator/internal/inference"
	"github.com/homelab-next/homelab-next/orchestrator/internal/profile"
	"github.com/homelab-next/homelab-next/orchestrator/internal/prompt"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// MaxResponseBytes bounds the answer stored for a job (and so what GET /jobs/{id} returns): a
// longer answer is cut at a character boundary, with a marker saying so.
const MaxResponseBytes = 1 << 20

// DefaultJobCeiling bounds a job whose pool sets no job deadline (Pool.JobTimeout() == 0: the
// configuration has neither runner.job_timeout_seconds nor runner.timeout_seconds), so no job runs
// without one. Config.JobCeiling overrides it.
const DefaultJobCeiling = 6 * time.Hour

// MaxBackendDownRequeues bounds how often one job goes back to the queue because every backend it
// may use was down; the next time it fails backend-down. Each admission gets the job's deadline
// afresh, so the requeues bound the job's total time too: at most this many plus one deadlines.
const MaxBackendDownRequeues = 5

// heartbeatInterval is how often a running job logs that it is still running. A var so a test
// can shorten it.
var heartbeatInterval = 10 * time.Minute

// retryBackoff is the pause before attempt n (n >= 2) of a profile's max_attempts: bounded linear,
// so an attempt that fails at once cannot spin through the budget in milliseconds. A var so tests
// can shorten it.
var retryBackoff = func(attempt int) time.Duration {
	return min(time.Duration(attempt-1)*time.Second, 5*time.Second)
}

// dispatch is what every attempt of one job shares.
type dispatch struct {
	job      *store.Job
	prof     *profile.Profile
	session  runner.Session // the attempt's session, but for its usage path
	usage    string         // the first attempt's usage path; "" = none
	affinity backends.Affinity
	locality backends.Locality
	start    time.Time // when the dispatch began: the findings check wants a newer file
}

// execute runs one admitted job to a terminal state (or back to queued). Every transition is a
// compare-and-swap on the state the executor last wrote: one that loses (a cancel moved the row)
// stops it, and nothing it would have written after is written. Nothing here fails the scheduler:
// a job's failure is recorded on the job. reserved is the backend Tick reserved, released exactly
// once on the way out (the claim held then, which a retry may have replaced).
func (sch *Scheduler) execute(ctx context.Context, job *store.Job, reserved string) {
	runID := job.RunID
	if err := sch.cfg.Store.UpdateState(runID, store.StateAdmitted, store.StateRunning); err != nil {
		sch.release(reserved, runID)
		sch.logf("queue: run=%s cannot mark running: %v", runID, err)
		return
	}
	requeued := false
	defer func() {
		if !requeued {
			sch.emitTerminal(runID)
		}
	}()
	defer func() { sch.release(reserved, runID) }()
	defer sch.takeWaitCause(runID)

	// Admission's row carries no task text (store.ListForAdmission); the executor reads its own.
	full, err := sch.cfg.Store.GetJob(runID)
	if err != nil {
		sch.failRunning(runID, "the job's row cannot be read")
		sch.logf("queue: run=%s cannot read its row: %v", runID, err)
		return
	}
	job = full

	prof, err := sch.resolve(job.AgentKey)
	if err != nil {
		sch.failRunning(runID, "no profile is registered for agent key "+job.AgentKey)
		return
	}
	d, reason := sch.prepare(ctx, job, prof)
	if reason != "" {
		sch.failRunning(runID, reason)
		return
	}
	// The job's deadline bounds its whole attempt chain, every max_attempts retry included: it
	// goes on the context once, here, so a retry gets no fresh budget.
	ctx, cancel := context.WithTimeout(ctx, sch.jobDeadline())
	defer cancel()
	res, attempt, outcome, err := sch.attempts(ctx, d, &reserved)
	if outcome == retryRequeued {
		requeued = true
		return
	}
	if err != nil && sch.requeueBackendDown(d, err, attempt, &reserved) {
		requeued = true
		return
	}
	class := ""
	if err != nil {
		class = classify(ctx, err, res)
	}
	sch.record(runID, res, err, class)
	if err != nil {
		sch.fail(ctx, d, res, err, class, attempt)
		return
	}
	if ok, checked := sch.findingWritten(prof, job.Shadow, d.start); checked && !ok {
		reason := store.FailureHandlerError + ": the run ended cleanly but wrote nothing under its findings prefix " + prof.FindingsPrefix(job.Shadow)
		sch.logf("queue: run=%s agent=%s %s", runID, job.AgentKey, reason)
		if uerr := sch.cfg.Store.UpdateExecutionResult(runID, res.UsedCloud, res.LocalAttempts, reason, ""); uerr != nil {
			sch.logf("queue: run=%s cannot record the result: %v", runID, uerr)
		}
		if uerr := sch.cfg.Store.UpdateStateClass(runID, store.StateRunning, store.StateFailed, store.FailureHandlerError); uerr != nil {
			sch.logf("queue: run=%s cannot mark failed: %v", runID, uerr)
		}
		return
	}
	if uerr := sch.cfg.Store.UpdateState(runID, store.StateRunning, store.StateDone); uerr != nil {
		sch.logf("queue: run=%s cannot mark done: %v", runID, uerr)
	}
}

// jobDeadline is the pool's job deadline, or the ceiling when the pool sets none.
func (sch *Scheduler) jobDeadline() time.Duration {
	if jt := sch.cfg.Pool.JobTimeout(); jt > 0 {
		return jt
	}
	if sch.cfg.JobCeiling > 0 {
		return sch.cfg.JobCeiling
	}
	return DefaultJobCeiling
}

// prepare builds what every attempt shares, or returns why the job cannot run (a class-prefixed
// reason) before any attempt starts: no task, a run id the gateway tag refuses, a prompt that
// cannot be built, grants that do not render, no toolsets.
func (sch *Scheduler) prepare(ctx context.Context, job *store.Job, prof *profile.Profile) (*dispatch, string) {
	runID := job.RunID
	start := time.Now()
	lane := runner.LaneReal
	if job.Shadow {
		lane = runner.LaneShadow
	}
	task := job.TaskDescription
	if task == "" {
		task = prof.DefaultTaskDescription
	}
	if task == "" {
		return nil, job.AgentKey + " needs a task_description: its profile has no default_task_description"
	}
	// One tag per run: every attempt's session carries it, and the job's finished record derives
	// the same value from the same prefix and run id (OutboxEventBuilder). A run id it refuses
	// fails the job here: no session ever runs untagged.
	tag, err := inference.GatewayTag(sch.cfg.GatewayTagPrefix, runID)
	if err != nil {
		return nil, "the run id cannot carry a gateway tag, so no session may start"
	}
	text, meta, err := prompt.Build(ctx, prompt.Input{
		Profile:   *prof,
		Index:     sch.cfg.Lessons,
		Task:      task,
		Lane:      lane,
		Contracts: sch.cfg.Contracts,
	})
	if err != nil {
		return nil, fmt.Sprintf("the prompt cannot be built: %v", err)
	}
	// A job requeued and admitted again keeps the provenance of its first dispatch.
	if job.PromptSHA256 == "" {
		if uerr := sch.cfg.Store.UpdatePromptProvenance(runID, meta.LessonUIDs, meta.RunbookUIDs, meta.SHA256, meta.Bytes); uerr != nil {
			sch.logf("queue: run=%s cannot record the prompt's provenance: %v", runID, uerr)
		}
	}
	// A profile with no grants block runs with the runner's own server set (nil); one with grants
	// gets exactly its lane's rendered servers.
	var servers map[string]runner.Server
	if !prof.Grants.IsZero() {
		if sch.cfg.Grants == nil {
			return nil, job.AgentKey + " declares grants and no grants catalog is configured"
		}
		servers, err = sch.cfg.Grants.Render(prof.Grants.Lane(job.Shadow), prof.GrantOwner(job.Shadow))
		if err != nil {
			return nil, fmt.Sprintf("%s grants do not render: %v", job.AgentKey, err)
		}
	}
	toolsets, err := prof.LaneToolsets(lane)
	if err != nil {
		return nil, fmt.Sprintf("%s toolsets: %v", job.AgentKey, err)
	}
	if len(toolsets) == 0 {
		return nil, fmt.Sprintf("%s has no toolsets for the %s lane", job.AgentKey, lane)
	}
	if uerr := sch.cfg.Store.UpdateProfileRevision(runID, prof.Revision); uerr != nil {
		sch.logf("queue: run=%s cannot record the profile revision: %v", runID, uerr)
	}
	usage := ""
	if sch.cfg.UsageDir != "" {
		// One directory per run, so a runner can give a session write access to its own run's
		// reports only, and no session can write a file another run's sum would read.
		if merr := os.MkdirAll(runUsageDir(sch.cfg.UsageDir, runID), 0o700); merr != nil {
			sch.logf("queue: run=%s no usage report: cannot create the usage directory: %v", runID, merr)
		} else {
			usage = filepath.Join(runUsageDir(sch.cfg.UsageDir, runID), runID+".json")
		}
	}
	return &dispatch{
		job:  job,
		prof: prof,
		session: runner.Session{
			RunID:      runID,
			AgentKey:   job.AgentKey,
			Lane:       lane,
			Prompt:     text,
			Toolsets:   toolsets,
			Servers:    servers,
			GatewayTag: tag,
		},
		usage:    usage,
		affinity: backends.AffinityOf(prof.BackendAffinity),
		locality: backends.LocalityOf(prof.LocalOnly),
		start:    start,
	}, ""
}

// attempts runs the attempt chain up to the profile's max_attempts, each under ctx (the job's
// deadline), keeping the run id. It returns the last Call's result and error, the last attempt's
// number, and retryRequeued when a drain put the job back in the queue.
func (sch *Scheduler) attempts(ctx context.Context, d *dispatch, reserved *string) (*backends.Result, int, retryDecision, error) {
	runID := d.job.RunID
	maxAttempts := max(d.prof.MaxAttempts, 1)
	start := time.Now()
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(heartbeatInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				sch.logf("queue: run=%s agent=%s still running after %s", runID, d.job.AgentKey, time.Since(start).Round(time.Second))
			}
		}
	}()
	var res *backends.Result
	var err error
	// A job requeued between attempts (a drain) resumes its count.
	first := d.job.Attempts + 1
	attempt := first
	for ; ; attempt++ {
		if attempt > first {
			switch sch.retryGate(ctx, d, reserved, attempt) {
			case retryStop:
				attempt--
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					err = fmt.Errorf("%w (before attempt %d): %w", backends.ErrJobDeadline, attempt+1, err)
				}
				return res, attempt, retryStop, err
			case retryRequeued:
				return res, attempt - 1, retryRequeued, err
			}
		}
		s := d.session
		s.UsagePath = attemptUsagePath(d.usage, attempt)
		res, err = sch.cfg.Pool.Call(ctx, s, d.locality, d.affinity, *reserved)
		if res == nil {
			res = &backends.Result{}
		}
		if uerr := sch.cfg.Store.UpdateAttempts(runID, attempt); uerr != nil {
			sch.logf("queue: run=%s cannot record the attempt count: %v", runID, uerr)
		}
		if err == nil || attempt >= maxAttempts || !mayRetryAttempt(ctx, err) {
			// Another attempt was due and the job's deadline ended it: that is the class, whatever
			// the last attempt failed with as the deadline passed.
			if err != nil && attempt < maxAttempts && !spentBudget(err) && errors.Is(ctx.Err(), context.DeadlineExceeded) {
				err = fmt.Errorf("%w (before attempt %d): %w", backends.ErrJobDeadline, attempt+1, err)
			}
			return res, attempt, retryGo, err
		}
		sch.logf("queue: run=%s attempt %d/%d failed (%s), retrying", runID, attempt, maxAttempts, res.LocalFailedReason)
	}
}

// retryDecision is retryGate's verdict on the next attempt.
type retryDecision int

const (
	retryGo       retryDecision = iota // run the next attempt
	retryStop                          // stop: the job is no longer ours to run, or its time is up
	retryRequeued                      // the job went back to queued (its backend was drained)
)

// retryGate runs before every attempt after the first: the backoff (ended early by the job's
// context), then the row must still read running (a cancel moves it before it cancels the
// context, and an attempt that failed in between must not start another session), then a drained
// reservation is given back and admission runs again; when nothing else has room the job goes
// back to queued, its attempts kept, and waits like any job on a drained backend.
func (sch *Scheduler) retryGate(ctx context.Context, d *dispatch, reserved *string, attempt int) retryDecision {
	runID := d.job.RunID
	if wait := retryBackoff(attempt); wait > 0 {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return retryStop
		case <-t.C:
		}
	}
	if ctx.Err() != nil {
		return retryStop
	}
	cur, err := sch.cfg.Store.GetJob(runID)
	if err != nil {
		sch.logf("queue: run=%s cannot read the job before attempt %d, not retrying: %v", runID, attempt, err)
		return retryStop
	}
	if cur.State != store.StateRunning {
		sch.logf("queue: run=%s is %s before attempt %d: no further attempt", runID, cur.State, attempt)
		return retryStop
	}
	if *reserved == "" || !sch.cfg.Pool.Drained(*reserved) {
		return retryGo
	}
	drained := *reserved
	sch.release(drained, runID)
	*reserved = ""
	if next, ok := sch.reserve(ctx, d.job, d.prof); ok {
		*reserved = next
		sch.logf("queue: run=%s backend %s was drained before attempt %d: retrying on %q", runID, drained, attempt, next)
		return retryGo
	}
	if err := sch.cfg.Store.UpdateState(runID, store.StateRunning, store.StateQueued); err != nil {
		sch.logf("queue: run=%s backend %s was drained before attempt %d and the job cannot go back to the queue: %v", runID, drained, attempt, err)
		return retryStop
	}
	sch.logf("queue: run=%s backend %s was drained before attempt %d: back to queued with %d attempt(s) spent", runID, drained, attempt, attempt-1)
	return retryRequeued
}

// runUsageDir is runID's own usage directory under base. The run id is one the gateway tag
// accepted, so it is one path segment.
func runUsageDir(base, runID string) string { return filepath.Join(base, runID) }

// attemptUsagePath is attempt n's usage path: base for the first, base with ".aN" before its
// ".json" after. The pool derives one path per leg from it (backends.LegUsagePath).
func attemptUsagePath(base string, attempt int) string {
	if base == "" || attempt <= 1 {
		return base
	}
	return strings.TrimSuffix(base, ".json") + fmt.Sprintf(".a%d.json", attempt)
}

// record writes what the attempt chain left: the result (the answer only on success, bounded),
// the backend and the usage report summed over every session of the run, and the call sizing.
// Each write is best effort: an audit field that cannot be written never fails the job.
func (sch *Scheduler) record(runID string, res *backends.Result, callErr error, class string) {
	if sch.cfg.UsageDir != "" {
		if total, ok := sumRunUsage(runUsageDir(sch.cfg.UsageDir, runID), runID, res.Usage); ok {
			res.Usage = total
		}
	}
	// On a failure the Result is the last attempt's session (its usage, stderr and exit code),
	// and its Response may be a failure report: it is never the job's answer.
	answer := ""
	reason := res.LocalFailedReason
	if callErr == nil {
		answer = boundText(res.Response, MaxResponseBytes)
	} else {
		reason = classReason(class, res)
	}
	if uerr := sch.cfg.Store.UpdateExecutionResult(runID, res.UsedCloud, res.LocalAttempts, reason, answer); uerr != nil {
		sch.logf("queue: run=%s cannot record the result: %v", runID, uerr)
	}
	if uerr := sch.cfg.Store.UpdateTelemetry(runID, res.LocalBackendUsed, usageTokenCounts(res.Usage)); uerr != nil {
		sch.logf("queue: run=%s cannot record the telemetry: %v", runID, uerr)
	}
	if uf, ok := usageFields(res.Usage); ok || res.SessionID != "" {
		if res.SessionID != "" {
			uf.SessionID = res.SessionID
		}
		if uerr := sch.cfg.Store.UpdateUsageFields(runID, uf); uerr != nil {
			sch.logf("queue: run=%s cannot record the usage report: %v", runID, uerr)
		}
	}
	sch.persistCallSizing(runID, res.Usage)
}

// persistCallSizing writes the run's per-call sizing and why it waited, when either is known.
func (sch *Scheduler) persistCallSizing(runID string, usage map[string]any) {
	cs, _ := usageCallSizing(usage)
	cs.WaitCause = sch.takeWaitCause(runID)
	if cs.LastCallPromptTokens == nil && cs.MaxCallPromptTokens == nil && cs.MaxTokensRequested == nil && cs.WaitCause == "" {
		return
	}
	if err := sch.cfg.Store.UpdateCallSizing(runID, cs); err != nil {
		sch.logf("queue: run=%s cannot record the call sizing: %v", runID, err)
	}
}

// requeueBackendDown puts a local-only job whose every eligible backend was found down back in
// the queue, its run id kept: it did no work, and admission holds it there until a backend is up.
// The attempt does not count: neither against max_attempts nor as a first attempt spent (the
// count goes back to what it was), and nothing of it is recorded. After MaxBackendDownRequeues
// requeues the job fails backend-down instead. It reports whether it requeued.
func (sch *Scheduler) requeueBackendDown(d *dispatch, callErr error, attempt int, reserved *string) bool {
	if d.locality != backends.LocalOnly || !backends.IsBackendDown(callErr) || !mayAutoRequeue(callErr) {
		return false
	}
	runID := d.job.RunID
	sch.mu.Lock()
	n := sch.requeues[runID]
	sch.mu.Unlock()
	if n >= MaxBackendDownRequeues {
		sch.logf("queue: run=%s lost its backends %d times: failing it backend-down", runID, n+1)
		return false
	}
	// The claim goes back before the row reads queued, as a drained retry's does: once queued, a
	// pass may admit the run again and reserve under its run id, and a release after that would
	// drop the new claim.
	sch.release(*reserved, runID)
	*reserved = ""
	// The row goes back and the attempt is uncounted in one store operation: a pass that admits
	// the run between two writes would run it with the attempt it gave back still counted.
	if err := sch.cfg.Store.Requeue(runID, store.StateRunning, attempt-1); err != nil {
		sch.logf("queue: run=%s lost its backends and cannot go back to the queue: %v", runID, err)
		return false
	}
	sch.mu.Lock()
	if sch.requeues == nil {
		sch.requeues = map[string]int{}
	}
	sch.requeues[runID] = n + 1
	sch.mu.Unlock()
	sch.logf("queue: run=%s agent=%s local-only, every eligible backend is down: back to queued until one is up (%d of %d)", runID, d.job.AgentKey, n+1, MaxBackendDownRequeues)
	return true
}

// fail records the job's failure with its class and, when the environment is to blame, its one
// automatic retry, created in the failing transaction so the failed event already names it. A
// lost compare-and-swap (a cancel owns the outcome) creates no retry.
func (sch *Scheduler) fail(ctx context.Context, d *dispatch, res *backends.Result, callErr error, class string, attempt int) {
	job := d.job
	sch.logf("queue: run=%s agent=%s failed: %s", job.RunID, job.AgentKey, classReason(class, res))
	var retry *store.Job
	if mayAutoRequeue(callErr) && isSignalKill(callErr, res) {
		// One extra run after a kill, and only for a job whose profile did not already spend
		// more attempts: max_attempts > 1 has had its extra run.
		switch {
		case attempt > 1:
			sch.logf("queue: run=%s was killed on attempt %d: its profile's retries spent its budget, no automatic retry", job.RunID, attempt)
		case job.RetryOfRunID != "":
			sch.logf("queue: run=%s, a retry of %s, was killed too: no further retry", job.RunID, job.RetryOfRunID)
		default:
			retry = retryOf(job)
		}
	}
	if retry == nil && errors.Is(ctx.Err(), context.Canceled) && !spentSessionBudget(callErr) && attempt <= 1 &&
		job.RetryOfRunID == "" && !sch.identicalQueued(job) {
		// The controller is shutting down (an operator's cancel moved the row first, so its CAS
		// below loses and nothing is created): the job ran into no fault of its own. Bounded like
		// a kill's retry: one, for a first-attempt job that is no retry itself.
		retry = retryOf(job)
	}
	retried, retryErr, err := sch.cfg.Store.FailWithRetry(job.RunID, store.StateRunning, class, retry)
	switch {
	case err != nil:
		sch.logf("queue: run=%s cannot mark failed: %v", job.RunID, err)
	case retryErr != nil:
		sch.logf("queue: run=%s failed; its automatic retry was not created: %v", job.RunID, retryErr)
	case retried:
		sch.logf("queue: run=%s failed (%s); retried as run=%s", job.RunID, class, retry.RunID)
	}
}

// identicalQueued reports whether a queued job of the same submitter, agent, task and lane
// already waits.
func (sch *Scheduler) identicalQueued(job *store.Job) bool {
	queued, err := sch.cfg.Store.ListForAdmission(store.StateQueued)
	if err != nil {
		return false
	}
	k := keyOf(job)
	for _, q := range queued {
		if keyOf(q) == k {
			return true
		}
	}
	return false
}

// retryOf is the scheduler's automatic retry of job: a new run replaying its task, lane and
// priority, owned by its submitter.
func retryOf(job *store.Job) *store.Job {
	return &store.Job{
		RunID:           NewRunID(),
		AgentKey:        job.AgentKey,
		ProfileID:       job.ProfileID,
		Priority:        job.Priority,
		State:           store.StateQueued,
		Shadow:          job.Shadow,
		CreatedAt:       time.Now().UTC(),
		TaskDescription: job.TaskDescription,
		RetryOfRunID:    job.RunID,
		SubmittedBy:     job.SubmittedBy,
	}
}

// maxPreparedReason bounds a reason found before any attempt: a grants error can quote a value.
const maxPreparedReason = 512

// failRunning fails a running job for a reason found before any attempt (its configuration or
// its profile's), class handler-error: resubmitting it meets the same configuration.
func (sch *Scheduler) failRunning(runID, reason string) {
	reason = boundText(store.FailureHandlerError+": "+reason, maxPreparedReason)
	sch.logf("queue: run=%s %s", runID, reason)
	if err := sch.cfg.Store.UpdateExecutionResult(runID, false, 0, reason, ""); err != nil {
		sch.logf("queue: run=%s cannot record the result: %v", runID, err)
	}
	if err := sch.cfg.Store.UpdateStateClass(runID, store.StateRunning, store.StateFailed, store.FailureHandlerError); err != nil {
		sch.logf("queue: run=%s cannot mark failed: %v", runID, err)
	}
}
