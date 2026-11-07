// SPDX-License-Identifier: Apache-2.0

package store

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/events"
)

// The store is the events sender's durable outbox.
var _ events.Outbox = (*Store)(nil)

// OutboxEvent is one event to deliver: its id (the dedupe key) and its exact JSON body.
type OutboxEvent struct {
	ID   string
	Body []byte
}

// EventBuilder turns a job row, read again inside the transaction that just changed its state,
// into the events that transition publishes, in order (a failed run publishes its failed event
// and its finished record). An empty result enqueues nothing.
type EventBuilder func(j *Job) []OutboxEvent

type outboxConfig struct {
	build     EventBuilder
	maxRows   int
	onEnqueue func()
}

// notify wakes the sender after a commit that enqueued.
func (ob *outboxConfig) notify(enqueued bool) {
	if ob != nil && enqueued && ob.onEnqueue != nil {
		ob.onEnqueue()
	}
}

// DefaultOutboxMax bounds the outbox when EnableOutbox is given maxRows <= 0.
const DefaultOutboxMax = 10000

// EnableOutbox makes lifecycle transitions durable events. Entering running from admitted, and
// entering a terminal state (emitsEvent), enqueue build's events in the same transaction as the
// state change, so a crash never commits one without the other; ReconcileOrphans' sweep does the
// same. The outbox holds at most maxRows events: enqueueing into a full one drops the oldest,
// logs it and counts it (OutboxDropped), because the newest state is the one a consumer can still
// act on. onEnqueue (may be nil) runs after each commit that enqueued, to wake the sender.
func (s *Store) EnableOutbox(build EventBuilder, maxRows int, onEnqueue func()) {
	if maxRows <= 0 {
		maxRows = DefaultOutboxMax
	}
	s.outbox.Store(&outboxConfig{build: build, maxRows: maxRows, onEnqueue: onEnqueue})
}

// SetOutboxNotify replaces the wake-up after a commit (the sender is built after the store, so
// it is wired in a second step). It does nothing before EnableOutbox.
func (s *Store) SetOutboxNotify(onEnqueue func()) {
	if ob := s.outbox.Load(); ob != nil {
		c := *ob
		c.onEnqueue = onEnqueue
		s.outbox.Store(&c)
	}
}

// emitsEvent reports whether from -> to publishes: the started event (admitted -> running) or a
// terminal one. A job cancelled while still queued never started, so it publishes only its
// finished record (outcome cancelled, no start time); every job reaching a terminal state gets
// exactly one.
func emitsEvent(from, to State) bool {
	switch to {
	case StateRunning:
		return from == StateAdmitted
	case StateCancelled:
		return from == StateRunning || from == StateAwaitingInference || from == StateQueued
	case StateDone, StateFailed, StateBudgetKilled:
		return from == StateRunning || from == StateAwaitingInference
	}
	return false
}

// deferFinished: a run cancelled while running does not publish its finished record in the
// cancel's transaction. Its executor is still alive and records the run's final usage, output
// and exit reason after the cancel lands (the runner is stopped, then its usage report read), so
// a record built at the cancel would lack all of it. The cancel sets finished_pending instead,
// and EmitDeferredFinished builds the record from the final row: called by the executor after its
// last write, by the cancel itself when no executor is alive, or by ReconcileOrphans after a
// crash. It happens once: the flag is cleared in the transaction that enqueues, and the event id
// derives from the run id (a second insert of it is ignored).
func deferFinished(from, to State) bool {
	return to == StateCancelled && from == StateRunning
}

// EmitDeferredFinished enqueues runID's finished record if a cancel deferred it and the row is
// cancelled, clearing the flag in the same transaction. Otherwise (no outbox, nothing pending,
// already emitted) it does nothing, so a caller may call it unconditionally.
func (s *Store) EmitDeferredFinished(runID string) error {
	ob := s.outbox.Load()
	if ob == nil {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("emit deferred finished %s: begin: %w", runID, err)
	}
	defer tx.Rollback()
	enq, err := s.emitDeferredTx(tx, ob, runID)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("emit deferred finished %s: commit: %w", runID, err)
	}
	ob.notify(enq)
	return nil
}

// DeferredFinishedPending lists the cancelled runs whose finished record is still deferred. The
// scheduler's sweep emits those that have no live executor.
func (s *Store) DeferredFinishedPending() ([]string, error) {
	ids, err := runIDsIn(s.db, `SELECT run_id FROM jobs WHERE finished_pending = 1 AND state = ? ORDER BY seq ASC`, string(StateCancelled))
	if err != nil {
		return nil, fmt.Errorf("list deferred finished: %w", err)
	}
	return ids, nil
}

func (s *Store) emitDeferredTx(tx *sql.Tx, ob *outboxConfig, runID string) (bool, error) {
	res, err := tx.Exec(`UPDATE jobs SET finished_pending = 0 WHERE run_id = ? AND finished_pending = 1 AND state = ?`, runID, string(StateCancelled))
	if err != nil {
		return false, fmt.Errorf("emit deferred finished %s: %w", runID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	return s.enqueueForJob(tx, ob, runID)
}

func (s *Store) updateStateWithEvent(ob *outboxConfig, runID string, from, to State, class string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("update state %s to %s: begin: %w", runID, to, err)
	}
	defer tx.Rollback()
	res, err := execStateUpdate(tx, runID, from, to, class)
	if err != nil {
		return fmt.Errorf("update state %s to %s: %w", runID, to, err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("update state %s to %s: rows affected: %w", runID, to, err)
	} else if n == 0 {
		return ErrStateConflict
	}
	enq := false
	if deferFinished(from, to) {
		if _, err := tx.Exec(`UPDATE jobs SET finished_pending = 1 WHERE run_id = ?`, runID); err != nil {
			return fmt.Errorf("update state %s to %s: mark finished pending: %w", runID, to, err)
		}
	} else if enq, err = s.enqueueForJob(tx, ob, runID); err != nil {
		return fmt.Errorf("update state %s to %s: %w", runID, to, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("update state %s to %s: commit: %w", runID, to, err)
	}
	ob.notify(enq)
	return nil
}

// FailWithRetry moves runID from `from` to failed with class and, when retry is not nil, creates
// retry (the scheduler's own retry, RetryOfRunID = runID) in the same transaction, before the
// failed event is built in it, so that event already names the retry. A lost compare-and-swap
// (ErrStateConflict: a cancel owns the outcome) creates no retry. When only the retry cannot be
// created (the run already has one, say), the failure is still recorded without it: retried is
// false and retryErr says why.
func (s *Store) FailWithRetry(runID string, from State, class string, retry *Job) (retried bool, retryErr, err error) {
	if retry == nil {
		return false, nil, s.UpdateStateClass(runID, from, StateFailed, class)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, nil, fmt.Errorf("update state %s to failed: begin: %w", runID, err)
	}
	defer tx.Rollback()
	res, err := execStateUpdate(tx, runID, from, StateFailed, class)
	if err != nil {
		return false, nil, fmt.Errorf("update state %s to failed: %w", runID, err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return false, nil, fmt.Errorf("update state %s to failed: rows affected: %w", runID, err)
	} else if n == 0 {
		return false, nil, ErrStateConflict
	}
	if rerr := insertJobTx(tx, retry, nil); rerr != nil {
		tx.Rollback()
		return false, rerr, s.UpdateStateClass(runID, from, StateFailed, class)
	}
	ob := s.outbox.Load()
	enq := false
	if ob != nil && emitsEvent(from, StateFailed) {
		if enq, err = s.enqueueForJob(tx, ob, runID); err != nil {
			return false, nil, fmt.Errorf("update state %s to failed: %w", runID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, nil, fmt.Errorf("update state %s to failed: commit: %w", runID, err)
	}
	ob.notify(enq)
	return true, nil, nil
}

func (s *Store) reconcileOrphansWithEvents(ob *outboxConfig) (requeued, failed int, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, fmt.Errorf("reconcile: begin: %w", err)
	}
	defer tx.Rollback()
	requeued, failed, ids, err := reconcileTx(tx)
	if err != nil {
		return 0, 0, err
	}
	enqueued := false
	for _, id := range ids {
		enq, err := s.enqueueForJob(tx, ob, id)
		if err != nil {
			return 0, 0, fmt.Errorf("reconcile: %w", err)
		}
		enqueued = enqueued || enq
	}
	// A run cancelled while running whose executor died before it emitted the deferred
	// finished record: the row is as final as it will get.
	pending, err := runIDsIn(tx, `SELECT run_id FROM jobs WHERE finished_pending = 1 AND state = ? ORDER BY seq ASC`, string(StateCancelled))
	if err != nil {
		return 0, 0, fmt.Errorf("reconcile deferred finished: %w", err)
	}
	for _, id := range pending {
		enq, err := s.emitDeferredTx(tx, ob, id)
		if err != nil {
			return 0, 0, fmt.Errorf("reconcile deferred finished: %w", err)
		}
		enqueued = enqueued || enq
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("reconcile: commit: %w", err)
	}
	ob.notify(enqueued)
	return requeued, failed, nil
}

// enqueueForJob reads runID again inside tx, builds its events and inserts them in order (an
// event id already in the outbox is a duplicate and ignored).
func (s *Store) enqueueForJob(tx *sql.Tx, ob *outboxConfig, runID string) (bool, error) {
	j, err := scanJob(tx.QueryRow(`SELECT `+jobColumns+` FROM jobs WHERE run_id = ?`, runID))
	if err != nil {
		return false, fmt.Errorf("read job for event: %w", err)
	}
	evs := ob.build(j)
	for _, e := range evs {
		if err := s.insertOutbox(tx, ob.maxRows, e.ID, e.Body); err != nil {
			return false, err
		}
	}
	return len(evs) > 0, nil
}

func (s *Store) insertOutbox(tx *sql.Tx, maxRows int, id string, body []byte) error {
	res, err := tx.Exec(`INSERT OR IGNORE INTO event_outbox (event_id, body, created_at) VALUES (?, ?, ?)`,
		id, string(body), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("enqueue event %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil // a duplicate id: already queued
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM event_outbox`).Scan(&count); err != nil {
		return fmt.Errorf("count outbox: %w", err)
	}
	if over := count - maxRows; over > 0 {
		if _, err := tx.Exec(`DELETE FROM event_outbox WHERE seq IN (SELECT seq FROM event_outbox ORDER BY seq ASC LIMIT ?)`, over); err != nil {
			return fmt.Errorf("trim outbox: %w", err)
		}
		s.outboxDropped.Add(uint64(over))
		log.Printf("events: outbox full (%d), dropped the %d oldest undelivered event(s)", maxRows, over)
	}
	return nil
}

// EnqueueEvent adds one event outside any state change (idempotent by id).
func (s *Store) EnqueueEvent(id string, body []byte) error {
	ob := s.outbox.Load()
	if ob == nil {
		return fmt.Errorf("enqueue event %s: outbox not enabled", id)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.insertOutbox(tx, ob.maxRows, id, body); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	ob.notify(true)
	return nil
}

// PendingEvents returns up to limit (at least 1) undelivered events, oldest first.
func (s *Store) PendingEvents(limit int) ([]events.OutboxRecord, error) {
	rows, err := s.db.Query(`SELECT seq, event_id, body, attempts FROM event_outbox ORDER BY seq ASC LIMIT ?`, max(limit, 1))
	if err != nil {
		return nil, fmt.Errorf("read outbox: %w", err)
	}
	defer rows.Close()
	var out []events.OutboxRecord
	for rows.Next() {
		var r events.OutboxRecord
		var body string
		if err := rows.Scan(&r.Seq, &r.ID, &body, &r.Attempts); err != nil {
			return nil, fmt.Errorf("read outbox: %w", err)
		}
		r.Body = []byte(body)
		out = append(out, r)
	}
	return out, rows.Err()
}

// AckEvent removes a delivered (or permanently refused) event.
func (s *Store) AckEvent(seq int64) error {
	_, err := s.db.Exec(`DELETE FROM event_outbox WHERE seq = ?`, seq)
	return err
}

// MarkEventAttempt counts one failed delivery attempt.
func (s *Store) MarkEventAttempt(seq int64) error {
	_, err := s.db.Exec(`UPDATE event_outbox SET attempts = attempts + 1 WHERE seq = ?`, seq)
	return err
}

// OutboxDropped is the number of events the size bound dropped since this process started.
func (s *Store) OutboxDropped() uint64 { return s.outboxDropped.Load() }

// OutboxLen is the number of undelivered events.
func (s *Store) OutboxLen() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM event_outbox`).Scan(&n)
	return n, err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
