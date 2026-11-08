// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"errors"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// DefaultOrphanGrace is how long an admitted, running or awaiting_inference row may have no live
// executor before the orphan sweep settles it.
//
// A row without an entry in execs has no executor: every executor puts its entry in place before
// its goroutine starts (so before its row can read running) and removes only its own after
// execute has returned (after its final write was tried); no executor retries a failed final
// write. What the grace absorbs: Ticks overlap, so one Tick's sweep can read a row another has
// just admitted microseconds before that one inserts the entry, and a row read as running can
// finish, or be requeued and admitted again, between the read and the check. The settling write
// is a compare-and-swap on the state read, which absorbs the second; the grace (a row must look
// orphaned for that long) absorbs the first. It is long on purpose: an orphan costs its agent's
// shadow slot and its reservation until then, which is cheap next to failing a live run, and the
// state-only compare-and-swap would let a run requeued and admitted again under the same id
// between the read and the write through (reachable only if the row also looked orphaned for the
// whole grace).
const DefaultOrphanGrace = 10 * time.Minute

// orphanErrLogEvery bounds how often an orphan that keeps failing to settle is logged.
const orphanErrLogEvery = 10 * time.Minute

// reservationReapGrace: a reservation younger than this is never reaped. A var so a test can
// shorten it.
var reservationReapGrace = 2 * time.Minute

// sweepOrphanedRuns (every Tick) settles rows that claim to be in flight with no executor in this
// process, as store.ReconcileOrphans does at startup: running or awaiting_inference becomes failed
// (class unknown, store.OrphanFailedReason, its terminal events enqueued in the same transaction);
// admitted goes back to queued (nothing ran, and the state machine has no admitted -> failed). A
// failed store read skips the sweep (never fail a run on a guess); a lost compare-and-swap means
// the row moved on by itself; any other error keeps the row's first-seen time, so the next sweep
// retries it without a fresh grace.
func (sch *Scheduler) sweepOrphanedRuns() {
	grace := sch.cfg.OrphanGrace
	if grace < 0 {
		return
	}
	if grace == 0 {
		grace = DefaultOrphanGrace
	}
	now := time.Now()
	type orphan struct {
		job   *store.Job
		from  store.State
		since time.Time
	}
	var due []orphan
	seen := map[string]time.Time{}
	for _, st := range []store.State{store.StateRunning, store.StateAwaitingInference, store.StateAdmitted} {
		jobs, err := sch.cfg.Store.ListByState(st)
		if err != nil {
			sch.logf("queue: orphan sweep skipped: %v", err)
			return
		}
		sch.mu.Lock()
		for _, j := range jobs {
			if _, live := sch.execs[j.RunID]; live {
				continue
			}
			since, ok := sch.orphanSince[j.RunID]
			if !ok {
				since = now
			}
			if now.Sub(since) < grace {
				seen[j.RunID] = since
				continue
			}
			due = append(due, orphan{job: j, from: st, since: since})
		}
		sch.mu.Unlock()
	}
	sch.mu.Lock()
	prevLogged := sch.orphanErrLogged
	sch.mu.Unlock()
	errLogged := map[string]time.Time{}
	for _, o := range due {
		id := o.job.RunID
		err := sch.settleOrphan(o.job, o.from, grace)
		last, hadErr := prevLogged[id]
		switch {
		case err == nil:
			if hadErr {
				sch.logf("queue: orphan sweep: run=%s settled after earlier errors", id)
			}
		case errors.Is(err, store.ErrStateConflict):
			sch.logf("queue: orphan sweep: run=%s moved on by itself", id)
		default:
			seen[id] = o.since
			if !hadErr || now.Sub(last) >= orphanErrLogEvery {
				sch.logf("queue: orphan sweep: cannot settle run=%s (%s), retried every tick, logged at most every %s: %v", id, o.from, orphanErrLogEvery, err)
				last = now
			}
			errLogged[id] = last
		}
	}
	sch.mu.Lock()
	sch.orphanSince = seen
	sch.orphanErrLogged = errLogged
	sch.mu.Unlock()
}

// settleOrphan applies the sweep's decision to one row; the caller logs its errors.
func (sch *Scheduler) settleOrphan(j *store.Job, from store.State, grace time.Duration) error {
	if from == store.StateAdmitted {
		if err := sch.cfg.Store.UpdateState(j.RunID, store.StateAdmitted, store.StateQueued); err != nil {
			return err
		}
		sch.logf("queue: run=%s agent=%s was admitted with no live executor for over %s: back to queued", j.RunID, j.AgentKey, grace)
		return nil
	}
	if err := sch.cfg.Store.FailOrphan(j.RunID, from, store.OrphanFailedReason); err != nil {
		return err
	}
	sch.logf("queue: run=%s agent=%s was %s with no live executor for over %s: failed (%s)", j.RunID, j.AgentKey, from, grace, store.OrphanFailedReason)
	sch.emitTerminal(j.RunID)
	return nil
}

// reapStaleReservations gives back the claims of runs no longer admitted, running or
// awaiting_inference. The three states are read one after another, so a row moving between them
// can be missed for one pass; the reap grace covers it. A failed read reaps nothing.
func (sch *Scheduler) reapStaleReservations() {
	live := map[string]bool{}
	for _, st := range []store.State{store.StateAdmitted, store.StateRunning, store.StateAwaitingInference} {
		jobs, err := sch.cfg.Store.ListByState(st)
		if err != nil {
			return
		}
		for _, j := range jobs {
			live[j.RunID] = true
		}
	}
	if reaped := sch.cfg.Pool.ReapStaleReservations(live, reservationReapGrace); len(reaped) > 0 {
		sch.logf("queue: reaped the reservations of runs no longer in flight: %v", reaped)
	}
}

// emitTerminal counts runID's outcome once its executor (or the orphan sweep) has finished with
// it, and emits the finished record a cancel deferred to it. A row that is not terminal is logged
// and counts nothing.
func (sch *Scheduler) emitTerminal(runID string) {
	j, err := sch.cfg.Store.GetJob(runID)
	if err != nil {
		sch.logf("queue: run=%s cannot read the job to count its outcome: %v", runID, err)
		return
	}
	if _, ok := TerminalEventTypes(j.State); !ok {
		sch.logf("queue: run=%s returned with state=%s: no outcome recorded", runID, j.State)
		return
	}
	if j.State == store.StateCancelled {
		sch.emitDeferredFinished(runID)
	}
	sch.counters.record(j.State, j.Attempts)
}

// emitDeferredFinished emits runID's deferred finished record, if one is pending.
func (sch *Scheduler) emitDeferredFinished(runID string) {
	if err := sch.cfg.Store.EmitDeferredFinished(runID); err != nil {
		sch.logf("queue: run=%s cannot emit its deferred finished record: %v", runID, err)
	}
}

// sweepDeferredFinished (every Tick) emits each deferred finished record whose run has no live
// executor: the backstop for a path that left one pending with nobody to clear it (an emit that
// failed on a database error). The pending list is read before execs is checked: an executor that
// leaves execs after the read emits on its own way out (the emit happens once), and a run is in
// execs from admission, before it can be running and so before a cancel can defer anything.
func (sch *Scheduler) sweepDeferredFinished() {
	ids, err := sch.cfg.Store.DeferredFinishedPending()
	if err != nil {
		sch.logf("queue: deferred finished sweep skipped: %v", err)
		return
	}
	for _, id := range ids {
		sch.mu.Lock()
		_, live := sch.execs[id]
		sch.mu.Unlock()
		if !live {
			sch.emitDeferredFinished(id)
		}
	}
}
