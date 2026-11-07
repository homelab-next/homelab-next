// SPDX-License-Identifier: Apache-2.0

package store

import "time"

// State is a job's place in its lifecycle.
type State string

// The job states. done, failed, budget_killed and cancelled are terminal.
const (
	StateQueued            State = "queued"
	StateAdmitted          State = "admitted"
	StateRunning           State = "running"
	StateAwaitingInference State = "awaiting_inference"
	StateDone              State = "done"
	StateFailed            State = "failed"
	StateBudgetKilled      State = "budget_killed"
	StateCancelled         State = "cancelled"
)

// validTransitions is the state machine. admitted -> queued is an admission that lost its race
// going back to the queue; running -> queued is a retry of the attempt chain whose backend was
// drained meanwhile going back to wait for another.
var validTransitions = map[State][]State{
	StateQueued:            {StateAdmitted, StateCancelled},
	StateAdmitted:          {StateRunning, StateQueued},
	StateRunning:           {StateAwaitingInference, StateDone, StateFailed, StateBudgetKilled, StateCancelled, StateQueued},
	StateAwaitingInference: {StateRunning, StateFailed},
}

// AllStates lists every job state, in lifecycle order.
var AllStates = []State{
	StateQueued, StateAdmitted, StateRunning, StateAwaitingInference,
	StateDone, StateFailed, StateBudgetKilled, StateCancelled,
}

// ValidState reports whether s names a job state.
func ValidState(s State) bool {
	for _, v := range AllStates {
		if v == s {
			return true
		}
	}
	return false
}

// CanTransition reports whether moving a job from `from` to `to` is an edge of the state
// machine. A terminal state has no outgoing edge.
func CanTransition(from, to State) bool {
	for _, allowed := range validTransitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

// Job is one job row. A pointer field is nil until it is set: a zero time.Time is a real
// instant, so only nil says "not yet".
type Job struct {
	RunID           string
	AgentKey        string
	ProfileID       string
	ProfileRevision string
	Priority        int
	// Seq is assigned by CreateJob: unique, increasing in submission order, never reused.
	Seq               int64
	State             State
	Shadow            bool
	LocalAttempts     int
	Attempts          int // runs of the whole attempt chain (the profile's max_attempts)
	CloudFallbackUsed bool
	LocalFailedReason string
	// SessionID is the runner's own id for the session it ran (column session_id).
	SessionID string
	// IdempotencyKey, when not empty, is unique across every job the database has ever held:
	// a key is never released, whatever state its job reaches and however old it is, so a
	// replayed submit always finds its first run (ErrDuplicateIdempotencyKey).
	IdempotencyKey string
	CreatedAt      time.Time
	StartedAt      *time.Time
	Deadline       *time.Time
	FinishedAt     *time.Time
	ResultPath     string
	EvidenceRefs   string

	// RetryOfRunID is set when this job retries another run: the scheduler's own retry of a
	// run its environment failed (capacity, an unreachable backend), or a caller's resubmit
	// (CreateResubmit). A run has at most one retry, whoever asks for it, and a retry is never
	// retried again (Resubmits caps the lineage at depth 1).
	RetryOfRunID string

	// SubmittedBy is the authenticated caller that submitted the job; empty with the API's
	// auth off. A retry belongs to its parent's submitter.
	SubmittedBy string

	// FailureClass is why a failed run failed (a Failure* constant), recorded by the failing
	// transition; "" when none was recorded. FailureReason reads it, and covers budget_killed
	// and cancelled too.
	FailureClass string
	// Resubmits is how many retries precede this run in its RetryOfRunID lineage: 0 for an
	// original submit, 1 for a retry, which is the ceiling.
	Resubmits int
	// RetriedByRunID is the run that retries this one, or "". It is derived on read from the
	// retry's retry_of_run_id and never written.
	RetriedByRunID string
	// ParentProfileRevision is, on a retry, the profile revision its parent ran with,
	// recorded when the retry is created. A retry replays its parent's task, but dispatch
	// resolves the profile by agent key when it runs, so it runs whatever revision is current
	// then; ProfileRevisionDrift says when that differs. "" when this is not a retry or the
	// parent never resolved a profile.
	ParentProfileRevision string

	// TaskDescription is the task the run performs, in the caller's words: the input the
	// prompt is built from. Empty is valid.
	TaskDescription string

	// ResponseBody is what the run produced (the runner's response text), stored when the run
	// reaches a terminal state; empty until then and on runs that produced nothing.
	ResponseBody string

	// LocalBackendUsed is the pool backend the run landed on ("" for none, or not recorded).
	// The four counters are the runner's usage report, summed over the run's attempts, with
	// an unknown count read as 0; Usage keeps unknown apart from zero.
	LocalBackendUsed string
	InputTokens      int
	OutputTokens     int
	ReasoningTokens  int
	APICalls         int

	// The rest of the usage report and the prompt's provenance. Completed and Failed are nil
	// until a report carried them. CostUSD and CacheReadTokens read an unknown value as 0
	// (Usage keeps it apart). AuxByTask is the report's per-task auxiliary usage as raw JSON.
	// InjectedLessons and InjectedRunbooks are comma-separated register ids; PromptSHA256 and
	// PromptBytes describe the final prompt handed to the runner.
	Completed        *bool
	Failed           *bool
	TurnExitReason   string
	CostUSD          float64
	CacheReadTokens  int
	AuxByTask        string
	InjectedLessons  string
	InjectedRunbooks string
	PromptSHA256     string
	PromptBytes      int

	// Usage is the usage counters as stored, nil meaning unknown (no report, or the report
	// lacked the key) and never zero. The job.finished usage record reads these.
	Usage Usage
	// Model is the model the run's last attempt asked its backend for; "" = unknown.
	Model string
}

// Usage holds a job's usage counters with unknown kept (nil) apart from zero.
type Usage struct {
	InputTokens     *int
	OutputTokens    *int
	ReasoningTokens *int
	CacheReadTokens *int
	APICalls        *int
	CostUSD         *float64
}

// Known reports whether any usage counter was recorded (a usage report was seen for the run).
func (u Usage) Known() bool {
	return u.InputTokens != nil || u.OutputTokens != nil || u.ReasoningTokens != nil ||
		u.CacheReadTokens != nil || u.APICalls != nil || u.CostUSD != nil
}
