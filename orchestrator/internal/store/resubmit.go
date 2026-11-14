// SPDX-License-Identifier: Apache-2.0

package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// Failure classes: why a run ended failed or budget_killed, recorded in failure_class by the
// failing transition and published as the failed event's `reason` (the enum of
// schemas/events/agent.job.failed.schema.json). capacity, stall, timeout and backend-down are
// faults of the environment, and the only classes a caller's resubmit may follow
// (RetryableFailureClass); deadline, cancelled, turn-cap and budget are decisions the controller
// made on purpose, which a retry would only repeat; handler-error and unknown are the job's own
// failure.
const (
	FailureCapacity     = "capacity"
	FailureStall        = "stall"
	FailureTimeout      = "timeout"
	FailureBackendDown  = "backend-down"
	FailureHandlerError = "handler-error"
	FailureDeadline     = "deadline"
	FailureCancelled    = "cancelled"
	FailureTurnCap      = "turn-cap"
	FailureBudget       = "budget"
	FailureUnknown      = "unknown"
)

// ProfileRevisionDrift reports whether j is a retry that ran (or is running) another profile
// revision than its parent did. A replay is deliberately not pinned to its parent's revision, a
// profile fix being the usual reason to retry, so this is information and never a refusal. It is
// false until the retry has resolved its own profile, and false when either revision is unknown.
func (j *Job) ProfileRevisionDrift() bool {
	return j.RetryOfRunID != "" && j.ParentProfileRevision != "" && j.ProfileRevision != "" &&
		j.ParentProfileRevision != j.ProfileRevision
}

// RetryableFailureClass reports whether a run that failed with class may be resubmitted.
func RetryableFailureClass(class string) bool {
	switch class {
	case FailureCapacity, FailureStall, FailureTimeout, FailureBackendDown:
		return true
	}
	return false
}

// FailureReason is j's failure class as published: the recorded class of a failed run (unknown
// when none was recorded: rows from before the column, and runs failed by startup
// reconciliation), budget for budget_killed, cancelled for cancelled, and "" in any other state.
func (j *Job) FailureReason() string {
	switch j.State {
	case StateFailed:
		if j.FailureClass != "" {
			return j.FailureClass
		}
		return FailureUnknown
	case StateBudgetKilled:
		return FailureBudget
	case StateCancelled:
		return FailureCancelled
	}
	return ""
}

// Resubmit refusal kinds: how the API answers (404, 409, 422).
const (
	RefusalNotFound      = "not_found"
	RefusalConflict      = "conflict"
	RefusalUnprocessable = "unprocessable"
)

// ResubmitRefusal is CreateJob's answer when a job with RetryOfRunID may not be created. Reason
// is machine-readable (a Refuse* constant); RetriedByRunID names the existing retry on
// already_retried; FailureClass is the parent's class on not_retryable and reason_mismatch.
type ResubmitRefusal struct {
	Kind           string
	Reason         string
	Detail         string
	RetriedByRunID string
	FailureClass   string
}

func (e *ResubmitRefusal) Error() string {
	return "resubmit refused: " + e.Reason + ": " + e.Detail
}

// Machine-readable resubmit refusal reasons.
const (
	RefuseUnknownRun       = "unknown_run"        // 404: no such run, or another caller's
	RefuseAgentKeyMismatch = "agent_key_mismatch" // 422
	RefuseNotFailed        = "not_failed"         // 422: still in flight, or done
	RefuseNotRetryable     = "not_retryable"      // 422: the class is a decision, or the job's own fault
	RefuseReasonMismatch   = "reason_mismatch"    // 422: the caller's reason is not the recorded class
	RefusePayloadOverride  = "payload_override"   // 422: a resubmit replays its parent's task and cannot carry its own
	RefuseAlreadyRetried   = "already_retried"    // 409: the run already has its one retry
	RefuseRetryChainSpent  = "retry_chain_spent"  // 409: the run is itself a retry
)

// ResubmitCheck is the policy CreateResubmit applies, inside its transaction, to a job whose
// RetryOfRunID an external caller set. The scheduler's own retries pass none: they decide
// retryability from the typed error, and only the one-retry-per-run rule every retry shares
// bounds them.
type ResubmitCheck struct {
	// MayAccess reports whether the caller may see the parent, given its submitter; false is
	// answered exactly like a missing run, so a caller cannot probe another's run ids.
	MayAccess func(submittedBy string) bool
	// Reason, when not empty, is the failure class the caller believes the parent failed with;
	// it must equal the recorded one.
	Reason string
	// Limits bound the resubmit's submitter like any submit (CreateSubmit).
	Limits SubmitLimits
}

// checkResubmit checks j (RetryOfRunID set) against its parent inside tx and fills in j's task
// and lineage depth from it. check is nil for the scheduler's own retries.
func checkResubmit(tx *sql.Tx, j *Job, check *ResubmitCheck) error {
	parent, err := scanJob(tx.QueryRow(`SELECT `+jobColumns+` FROM jobs WHERE run_id = ?`, j.RetryOfRunID))
	notFound := errors.Is(err, sql.ErrNoRows)
	if notFound && check == nil {
		// The scheduler retries a run it has just failed, so a missing parent is not a
		// caller's mistake to answer. One retry per id still holds (the unique index).
		j.Resubmits = 1
		return nil
	}
	if notFound {
		return &ResubmitRefusal{Kind: RefusalNotFound, Reason: RefuseUnknownRun, Detail: "retry_of_run_id names no run of this caller"}
	}
	if err != nil {
		return fmt.Errorf("read retry parent: %w", err)
	}
	j.ParentProfileRevision = parent.ProfileRevision
	if check != nil {
		if err := checkCallerResubmit(j, parent, check); err != nil {
			return err
		}
	}
	if parent.Resubmits > 0 {
		return &ResubmitRefusal{Kind: RefusalConflict, Reason: RefuseRetryChainSpent,
			Detail: "run " + parent.RunID + " is itself the retry of " + parent.RetryOfRunID + "; a job is resubmitted at most once"}
	}
	if parent.RetriedByRunID != "" {
		return &ResubmitRefusal{Kind: RefusalConflict, Reason: RefuseAlreadyRetried, RetriedByRunID: parent.RetriedByRunID,
			Detail: "run " + parent.RunID + " was already retried by " + parent.RetriedByRunID}
	}
	j.Resubmits = parent.Resubmits + 1
	return nil
}

// checkCallerResubmit is the external caller's part of checkResubmit: owner, agent key, a failed
// state with a retryable class, and no payload of its own. On success j takes its parent's task,
// owner, profile and lane.
func checkCallerResubmit(j, parent *Job, check *ResubmitCheck) error {
	if check.MayAccess != nil && !check.MayAccess(parent.SubmittedBy) {
		return &ResubmitRefusal{Kind: RefusalNotFound, Reason: RefuseUnknownRun, Detail: "retry_of_run_id names no run of this caller"}
	}
	if parent.AgentKey != j.AgentKey {
		return &ResubmitRefusal{Kind: RefusalUnprocessable, Reason: RefuseAgentKeyMismatch,
			Detail: fmt.Sprintf("run %s is agent_key %q, not %q", parent.RunID, parent.AgentKey, j.AgentKey)}
	}
	class := parent.FailureReason()
	switch parent.State {
	case StateFailed, StateBudgetKilled:
	case StateCancelled:
		return &ResubmitRefusal{Kind: RefusalUnprocessable, Reason: RefuseNotRetryable, FailureClass: class,
			Detail: "run " + parent.RunID + " was cancelled"}
	default:
		return &ResubmitRefusal{Kind: RefusalUnprocessable, Reason: RefuseNotFailed,
			Detail: fmt.Sprintf("run %s is %s, not failed", parent.RunID, parent.State)}
	}
	if check.Reason != "" && check.Reason != class {
		return &ResubmitRefusal{Kind: RefusalUnprocessable, Reason: RefuseReasonMismatch, FailureClass: class,
			Detail: fmt.Sprintf("run %s failed with %q, not %q", parent.RunID, class, check.Reason)}
	}
	if !RetryableFailureClass(class) {
		return &ResubmitRefusal{Kind: RefusalUnprocessable, Reason: RefuseNotRetryable, FailureClass: class,
			Detail: fmt.Sprintf("run %s failed with %q; only capacity, stall, timeout and backend-down are resubmitted", parent.RunID, class)}
	}
	if j.TaskDescription != "" || j.ProfileID != "" {
		return &ResubmitRefusal{Kind: RefusalUnprocessable, Reason: RefusePayloadOverride,
			Detail: "a resubmit replays run " + parent.RunID + "'s own task; omit task_description and profile_id"}
	}
	if j.Shadow && !parent.Shadow {
		return &ResubmitRefusal{Kind: RefusalUnprocessable, Reason: RefusePayloadOverride,
			Detail: "run " + parent.RunID + " is not a shadow run; a resubmit keeps its lane"}
	}
	j.TaskDescription = parent.TaskDescription
	// The retry belongs to the parent's owner, whoever asked for it (an admin resubmitting
	// another caller's run), as the scheduler's own retries do; otherwise the owner's next
	// resubmit would get a 409 naming a run that is a 404 to them.
	j.SubmittedBy = parent.SubmittedBy
	j.ProfileID = parent.ProfileID
	j.Shadow = parent.Shadow
	return nil
}

// CreateResubmit is CreateJob for a job an external caller submitted with retry_of_run_id. The
// parent is checked against check (owner, agent key, failed with a retryable class, at most one
// retry, never of a retry) and the job takes the parent's task, all in CreateJob's single write
// transaction, so two concurrent resubmits of one run cannot both succeed. An idempotency key
// already in use is reported first (ErrDuplicateIdempotencyKey), so a replayed resubmit finds its
// run rather than a 409. A refusal is a *ResubmitRefusal.
func (s *Store) CreateResubmit(j *Job, check ResubmitCheck) error {
	if j.RetryOfRunID == "" {
		return fmt.Errorf("CreateResubmit: RetryOfRunID is empty")
	}
	return s.createJob(j, &check, nil)
}

// RetriedBy returns the run id of runID's retry, or "".
func (s *Store) RetriedBy(runID string) (string, error) {
	var child string
	err := s.db.QueryRow(`SELECT run_id FROM jobs WHERE retry_of_run_id = ? ORDER BY seq ASC LIMIT 1`, runID).Scan(&child)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return child, err
}
