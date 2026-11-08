// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// Size caps. A submit body is bounded before it is decoded and its task before it is stored; a
// job's answer is bounded by the scheduler when it is stored (queue.MaxResponseBytes), so every
// response is bounded too.
const (
	// MaxSubmitBytes bounds a POST /jobs body.
	MaxSubmitBytes = 512 << 10
	// MaxTaskBytes bounds a task_description. The prompt built from it is bounded separately
	// (prompt.MaxPromptBytes).
	MaxTaskBytes = 256 << 10
)

// LegacySessionField is the session id's field name before the neutral names: served beside
// session_id, and accepted beside it as a filter, for the one overlap release ADR-0026's
// amendment sets. It goes no earlier than the release after the cutover.
const LegacySessionField = "hermes_session_id"

// SubmitRequest is POST /jobs's body.
type SubmitRequest struct {
	AgentKey  string `json:"agent_key"`
	ProfileID string `json:"profile_id"`
	// Priority is 1 (first) to 100; 0 is 50.
	Priority int `json:"priority"`
	// TaskDescription is the task, in the caller's words; empty uses the profile's default. At
	// most MaxTaskBytes.
	TaskDescription string `json:"task_description"`
	IdempotencyKey  string `json:"idempotency_key"`
	Shadow          bool   `json:"shadow"`
	// RetryOfRunID makes this the one resubmit of a failed run (store.CreateResubmit): it must
	// be the caller's, of the same agent key, failed with a retryable class, not a retry itself
	// and not retried already. It replays its parent's task, profile and lane, so
	// task_description and profile_id must be omitted.
	RetryOfRunID string `json:"retry_of_run_id,omitempty"`
	// Reason is the failure class the caller reacts to, only with retry_of_run_id; it must equal
	// the recorded one.
	Reason string `json:"reason,omitempty"`
	// Input and RequestBody are refused (400): there is no structured job input, and no HTTP
	// passthrough.
	Input       json.RawMessage `json:"input,omitempty"`
	RequestBody json.RawMessage `json:"request_body,omitempty"`
}

// SubmitResponse is a submit's answer: 201 for a new job, 200 for a replay.
type SubmitResponse struct {
	RunID        string `json:"run_id"`
	RetryOfRunID string `json:"retry_of_run_id,omitempty"`
}

// SubmitError is the body of a refused submit with a machine-readable reason.
type SubmitError struct {
	Error          string `json:"error"`
	Reason         string `json:"reason"`
	RetryOfRunID   string `json:"retry_of_run_id,omitempty"`
	RetriedByRunID string `json:"retried_by_run_id,omitempty"`
	FailureClass   string `json:"failure_class,omitempty"`
}

// JobResponse is GET /jobs/{id}'s body.
type JobResponse struct {
	RunID             string     `json:"run_id"`
	AgentKey          string     `json:"agent_key"`
	State             string     `json:"state"`
	Priority          int        `json:"priority"`
	Shadow            bool       `json:"shadow"`
	TaskDescription   string     `json:"task_description,omitempty"`
	CloudFallbackUsed bool       `json:"cloud_fallback_used"`
	LocalFailedReason string     `json:"local_failed_reason,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	StartedAt         *time.Time `json:"started_at,omitempty"`
	FinishedAt        *time.Time `json:"finished_at,omitempty"`
	// Attempts is how many times the attempt chain ran; always present.
	Attempts int `json:"attempts"`
	// ResponseBody is the run's answer, once it succeeded.
	ResponseBody     string `json:"response_body,omitempty"`
	LocalBackendUsed string `json:"local_backend_used,omitempty"`
	InputTokens      int    `json:"input_tokens,omitempty"`
	OutputTokens     int    `json:"output_tokens,omitempty"`
	ReasoningTokens  int    `json:"reasoning_tokens,omitempty"`
	APICalls         int    `json:"api_calls,omitempty"`
	// SessionID is the runner's own session id; LegacySessionID the same value under its old name
	// (LegacySessionField), for the overlap release.
	SessionID        string   `json:"session_id,omitempty"`
	LegacySessionID  string   `json:"hermes_session_id,omitempty"`
	Completed        *bool    `json:"completed,omitempty"`
	Failed           *bool    `json:"failed,omitempty"`
	TurnExitReason   string   `json:"turn_exit_reason,omitempty"`
	CostUSD          *float64 `json:"cost_usd,omitempty"` // nil: no report gave one (never read as 0)
	CacheReadTokens  int      `json:"cache_read_tokens,omitempty"`
	InjectedLessons  string   `json:"injected_lessons,omitempty"`
	InjectedRunbooks string   `json:"injected_runbooks,omitempty"`
	PromptSHA256     string   `json:"prompt_sha256,omitempty"`
	PromptBytes      int      `json:"prompt_bytes,omitempty"`
	Model            string   `json:"model,omitempty"`
	// The retry lineage: the run this one retries, the run that retried it, and how many retries
	// precede it (0: an original submit).
	RetryOfRunID   string `json:"retry_of_run_id,omitempty"`
	RetriedByRunID string `json:"retried_by_run_id,omitempty"`
	Resubmits      int    `json:"resubmits"`
	// FailureClass is why a failed, budget_killed or cancelled run ended.
	FailureClass string `json:"failure_class,omitempty"`
	// ProfileRevision is the revision the run resolved; on a retry, ParentProfileRevision is its
	// parent's, and ProfileRevisionDrift says they differ.
	ProfileRevision       string `json:"profile_revision,omitempty"`
	ParentProfileRevision string `json:"parent_profile_revision,omitempty"`
	ProfileRevisionDrift  bool   `json:"profile_revision_drift,omitempty"`
}

func newRunID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // never fails: crypto/rand.Read aborts the process instead
	return hex.EncodeToString(b)
}

func submitError(w http.ResponseWriter, status int, e SubmitError) { writeJSON(w, status, e) }

// The per-caller bounds' defaults (Config.MaxUnfinishedPerCaller, MaxSubmitsPerWindow,
// SubmitWindow).
const (
	DefaultMaxUnfinishedPerCaller = 1000
	DefaultMaxSubmitsPerWindow    = 2000
	DefaultSubmitWindow           = time.Hour
)

// Bounds of a resubmit's fields: a run id the API creates is 32 characters, a failure class is
// one short word.
const (
	maxRetryOfLen = 64
	maxReasonLen  = 32
)

// maxProfileIDLen bounds a submit's profile_id.
const maxProfileIDLen = 128

// submitFields are SubmitRequest's JSON keys, exactly as spelled: a body's keys must be these, each
// at most once.
var submitFields = map[string]bool{
	"agent_key": true, "profile_id": true, "priority": true, "task_description": true, "idempotency_key": true,
	"shadow": true, "retry_of_run_id": true, "reason": true, "input": true, "request_body": true,
}

// errNotStrict is a body that is not exactly one JSON object of SubmitRequest's keys.
var errNotStrict = errors.New("not one JSON object of the submit's keys")

// decodeSubmit decodes a submit body strictly: one JSON object, nothing after it, every key one of
// SubmitRequest's spelled exactly (encoding/json alone would match "Agent_Key" and take the last
// of two "input" keys), none repeated, and no unknown key.
func decodeSubmit(body []byte, req *SubmitRequest) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errNotStrict
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		key, ok := t.(string)
		if err != nil || !ok || !submitFields[key] || seen[key] {
			return errNotStrict
		}
		seen[key] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return errNotStrict
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return errNotStrict
	}
	if _, err := dec.Token(); err != io.EOF {
		return errNotStrict
	}
	strict := json.NewDecoder(bytes.NewReader(body))
	strict.DisallowUnknownFields()
	if err := strict.Decode(req); err != nil {
		return errNotStrict
	}
	return nil
}

// validProfileID is at most maxProfileIDLen of [A-Za-z0-9._:-], starting with a letter or digit.
func validProfileID(id string) bool {
	if len(id) < 1 || len(id) > maxProfileIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || (c != '.' && c != '_' && c != ':' && c != '-')) {
			return false
		}
	}
	return true
}

func handleSubmit(s *store.Store, agentKnown func(string) bool, limits store.SubmitLimits) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxSubmitBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "the request body is larger than "+strconv.Itoa(MaxSubmitBytes)+" bytes", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "the request body could not be read", http.StatusBadRequest)
			return
		}
		var req SubmitRequest
		if decodeSubmit(body, &req) != nil {
			submitError(w, http.StatusBadRequest, SubmitError{Reason: "invalid_body",
				Error: "the body must be one JSON object of the submit's keys, each spelled exactly and given once"})
			return
		}
		if req.AgentKey == "" {
			http.Error(w, "agent_key is required", http.StatusBadRequest)
			return
		}
		if h := r.Header.Get("Idempotency-Key"); h != "" {
			if req.IdempotencyKey != "" && req.IdempotencyKey != h {
				http.Error(w, "the Idempotency-Key header and idempotency_key differ", http.StatusBadRequest)
				return
			}
			req.IdempotencyKey = h
		}
		if len(req.IdempotencyKey) > store.MaxIdempotencyKeyLen {
			http.Error(w, "the idempotency key is longer than "+strconv.Itoa(store.MaxIdempotencyKeyLen)+" bytes", http.StatusBadRequest)
			return
		}
		switch {
		case len(req.Input) > 0 && string(req.Input) != "null":
			submitError(w, http.StatusBadRequest, SubmitError{Reason: "input_unsupported",
				Error: "input is not supported: give the task as task_description (a resubmit replays its parent's)"})
			return
		case len(req.RequestBody) > 0 && string(req.RequestBody) != "null":
			submitError(w, http.StatusBadRequest, SubmitError{Reason: "request_body_unsupported",
				Error: "request_body is not supported: the controller runs agent jobs only; send model calls to the gateway"})
			return
		case req.Reason != "" && req.RetryOfRunID == "":
			submitError(w, http.StatusBadRequest, SubmitError{Reason: "reason_without_retry", Error: "reason is only meaningful with retry_of_run_id"})
			return
		case len(req.TaskDescription) > MaxTaskBytes:
			http.Error(w, "task_description is larger than "+strconv.Itoa(MaxTaskBytes)+" bytes", http.StatusRequestEntityTooLarge)
			return
		}
		if len(req.RetryOfRunID) > maxRetryOfLen || len(req.Reason) > maxReasonLen {
			http.Error(w, "retry_of_run_id is at most "+strconv.Itoa(maxRetryOfLen)+" bytes and reason at most "+strconv.Itoa(maxReasonLen), http.StatusBadRequest)
			return
		}
		if req.ProfileID != "" && !validProfileID(req.ProfileID) {
			http.Error(w, "profile_id must be at most "+strconv.Itoa(maxProfileIDLen)+" of [A-Za-z0-9._:-], starting with a letter or digit", http.StatusBadRequest)
			return
		}
		// Before anything is stored, a resubmit's included: a job no profile can run is refused.
		if !agentKnown(req.AgentKey) {
			http.Error(w, "unknown agent_key: no profile is registered for it", http.StatusNotFound)
			return
		}
		if req.Priority == 0 {
			req.Priority = 50
		} else if req.Priority < 1 || req.Priority > 100 {
			http.Error(w, "priority must be between 1 and 100", http.StatusBadRequest)
			return
		}
		ctx := r.Context()
		j := &store.Job{
			RunID: newRunID(), AgentKey: req.AgentKey, ProfileID: req.ProfileID, Priority: req.Priority,
			State: store.StateQueued, Shadow: req.Shadow, IdempotencyKey: req.IdempotencyKey,
			CreatedAt: time.Now().UTC(), TaskDescription: req.TaskDescription,
			SubmittedBy: CallerFrom(ctx), RetryOfRunID: req.RetryOfRunID,
		}
		if req.RetryOfRunID != "" {
			err = s.CreateResubmit(j, store.ResubmitCheck{
				MayAccess: func(submittedBy string) bool { return mayAccessJob(ctx, submittedBy) },
				Reason:    req.Reason,
				Limits:    limits,
			})
		} else {
			err = s.CreateSubmit(j, limits)
		}
		var refusal *store.ResubmitRefusal
		switch {
		case err == nil:
			writeJSON(w, http.StatusCreated, SubmitResponse{RunID: j.RunID, RetryOfRunID: j.RetryOfRunID})
		case errors.As(err, &refusal):
			status := http.StatusUnprocessableEntity
			switch refusal.Kind {
			case store.RefusalNotFound:
				status = http.StatusNotFound
			case store.RefusalConflict:
				status = http.StatusConflict
			}
			submitError(w, status, SubmitError{Error: refusal.Detail, Reason: refusal.Reason,
				RetryOfRunID: req.RetryOfRunID, RetriedByRunID: refusal.RetriedByRunID, FailureClass: refusal.FailureClass})
		case errors.Is(err, store.ErrDuplicateIdempotencyKey):
			answerReplay(w, ctx, s, &req)
		case errors.Is(err, store.ErrTooManyUnfinished):
			http.Error(w, "too many unfinished jobs for this caller: wait for some to finish", http.StatusTooManyRequests)
		case errors.Is(err, store.ErrTooManySubmits):
			http.Error(w, "too many jobs submitted by this caller in the window: wait", http.StatusTooManyRequests)
		case errors.Is(err, store.ErrShadowBackpressure):
			http.Error(w, "the agent already has an unfinished shadow job", http.StatusTooManyRequests)
		case errors.Is(err, store.ErrIdempotencyKeyTooLong):
			http.Error(w, "the idempotency key is too long", http.StatusBadRequest)
		default:
			log.Printf("api: submit: %v", err)
			http.Error(w, "internal error creating the job", http.StatusInternalServerError)
		}
	}
}

// keyOwner is the submitter a replayed key is looked up under: the store keeps a caller's resubmit
// under its parent's owner (an admin resubmitting another caller's run), so a replay is looked up
// there once the caller may see the parent, and under the caller's own name otherwise.
func keyOwner(ctx context.Context, s *store.Store, req *SubmitRequest) string {
	owner := CallerFrom(ctx)
	if req.RetryOfRunID == "" {
		return owner
	}
	parent, err := s.GetJob(req.RetryOfRunID)
	if err != nil || !mayAccessJob(ctx, parent.SubmittedBy) {
		return owner
	}
	return parent.SubmittedBy
}

// answerReplay answers a submit whose idempotency key is taken: 200 with the key's run when the
// request is the same submit again (same agent key and retry_of_run_id, and for an ordinary submit
// the same lane: a resubmit takes its parent's lane, whatever the request said), 422 when the key
// was used for a different submit.
func answerReplay(w http.ResponseWriter, ctx context.Context, s *store.Store, req *SubmitRequest) {
	existing, err := s.FindByIdempotencyKey(keyOwner(ctx, s, req), req.IdempotencyKey)
	if err != nil || !mayAccessJob(ctx, existing.SubmittedBy) {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			log.Printf("api: replay lookup: %v", err)
		}
		http.Error(w, "duplicate idempotency key, and its job cannot be resolved", http.StatusConflict)
		return
	}
	if existing.AgentKey != req.AgentKey || existing.RetryOfRunID != req.RetryOfRunID || (req.RetryOfRunID == "" && existing.Shadow != req.Shadow) {
		submitError(w, http.StatusUnprocessableEntity, SubmitError{Reason: "idempotency_key_mismatch", RetryOfRunID: req.RetryOfRunID,
			Error: "the idempotency key was already used for a different submit (agent_key, retry_of_run_id or shadow differs); use a new key"})
		return
	}
	writeJSON(w, http.StatusOK, SubmitResponse{RunID: existing.RunID, RetryOfRunID: existing.RetryOfRunID})
}

// jobFor reads runID for the request: another caller's job is a 404, like none.
func jobFor(w http.ResponseWriter, r *http.Request, s *store.Store) (*store.Job, bool) {
	j, err := s.GetJob(r.PathValue("id"))
	if err == nil && !mayAccessJob(r.Context(), j.SubmittedBy) {
		err = store.ErrNotFound
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.Error(w, "job not found", http.StatusNotFound)
		return nil, false
	case err != nil:
		log.Printf("api: get job: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, false
	}
	return j, true
}

func handleGetJob(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		j, ok := jobFor(w, r, s)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, JobResponse{
			RunID: j.RunID, AgentKey: j.AgentKey, State: string(j.State), Priority: j.Priority, Shadow: j.Shadow,
			TaskDescription: j.TaskDescription, CloudFallbackUsed: j.CloudFallbackUsed, LocalFailedReason: j.LocalFailedReason,
			CreatedAt: j.CreatedAt, StartedAt: j.StartedAt, FinishedAt: j.FinishedAt, Attempts: j.Attempts,
			ResponseBody: j.ResponseBody, LocalBackendUsed: j.LocalBackendUsed,
			InputTokens: j.InputTokens, OutputTokens: j.OutputTokens, ReasoningTokens: j.ReasoningTokens, APICalls: j.APICalls,
			SessionID: j.SessionID, LegacySessionID: j.SessionID, Completed: j.Completed, Failed: j.Failed,
			TurnExitReason: j.TurnExitReason, CostUSD: j.Usage.CostUSD, CacheReadTokens: j.CacheReadTokens,
			InjectedLessons: j.InjectedLessons, InjectedRunbooks: j.InjectedRunbooks,
			PromptSHA256: j.PromptSHA256, PromptBytes: j.PromptBytes, Model: j.Model,
			RetryOfRunID: j.RetryOfRunID, RetriedByRunID: j.RetriedByRunID, Resubmits: j.Resubmits,
			FailureClass: j.FailureReason(), ProfileRevision: j.ProfileRevision,
			ParentProfileRevision: j.ParentProfileRevision, ProfileRevisionDrift: j.ProfileRevisionDrift(),
		})
	}
}

// handleCancel moves the row to cancelled and then stops its live session (cancelRun): the row
// first, so an attempt that fails in between starts no other. A run with no live executor gets its
// finished record now; one with an executor gets it from the executor, after its final writes.
func handleCancel(s *store.Store, cancelRun func(string) bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		j, ok := jobFor(w, r, s)
		if !ok {
			return
		}
		if !store.CanTransition(j.State, store.StateCancelled) {
			http.Error(w, "the job is not in a cancellable state", http.StatusConflict)
			return
		}
		if err := s.UpdateState(j.RunID, j.State, store.StateCancelled); err != nil {
			if errors.Is(err, store.ErrStateConflict) {
				http.Error(w, "the job's state changed concurrently; cancel aborted", http.StatusConflict)
				return
			}
			log.Printf("api: cancel %q: %v", j.RunID, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if cancelRun == nil || !cancelRun(j.RunID) {
			if err := s.EmitDeferredFinished(j.RunID); err != nil {
				log.Printf("api: cancel %q: cannot emit the deferred finished record: %v", j.RunID, err)
			}
		}
		w.WriteHeader(http.StatusOK)
	}
}

// handleReloadProfiles reloads the profiles; a failed reload leaves the loaded ones in force and
// answers 500 (the reason is in the controller's log, not the response).
func handleReloadProfiles(reload func() error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if reload == nil {
			http.Error(w, "profile reload is not configured", http.StatusNotImplemented)
			return
		}
		if err := reload(); err != nil {
			log.Printf("api: profile reload by %q failed, the loaded profiles stay: %v", callerOrAnonymous(r), err)
			http.Error(w, "the reload failed and the loaded profiles stay in force (see the controller's log)", http.StatusInternalServerError)
			return
		}
		log.Printf("api: profiles reloaded by %q", callerOrAnonymous(r))
		w.WriteHeader(http.StatusOK)
	}
}

// maxStatusBytes bounds what the backend status command's output may be.
const maxStatusBytes = 1 << 20

// handleBackendStatus returns the site's status command's output as it is.
func handleBackendStatus(status func(context.Context) ([]byte, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if status == nil {
			http.Error(w, "backend status is not configured", http.StatusNotImplemented)
			return
		}
		out, err := status(r.Context())
		if err != nil {
			log.Printf("api: backend status: %v", err)
			http.Error(w, "the backend status command failed (see the controller's log)", http.StatusInternalServerError)
			return
		}
		if len(out) > maxStatusBytes {
			http.Error(w, "the backend status command's output is too large", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	}
}

// BackendEligibilityEntry is one profile's verdict on one backend (the scheduler's own type has
// the same fields; the API does not import the scheduler).
type BackendEligibilityEntry struct {
	AgentKey string `json:"agent_key"`
	Eligible bool   `json:"eligible"`
	Reason   string `json:"reason,omitempty"`
}

func handleBackendEligibility(eligibility func(string) ([]BackendEligibilityEntry, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if eligibility == nil {
			http.Error(w, "backend eligibility is not configured", http.StatusNotImplemented)
			return
		}
		backend := r.URL.Query().Get("backend")
		if backend == "" {
			http.Error(w, "?backend=<name> is required", http.StatusBadRequest)
			return
		}
		entries, err := eligibility(backend)
		if err != nil {
			http.Error(w, "backend not found", http.StatusNotFound)
			return
		}
		if entries == nil {
			entries = []BackendEligibilityEntry{}
		}
		writeJSON(w, http.StatusOK, entries)
	}
}

// handleBackendThroughput is a backend's output rate over its recent finished jobs (?limit=, at
// most 1000).
func handleBackendThroughput(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		backend := r.URL.Query().Get("backend")
		if backend == "" {
			http.Error(w, "?backend=<name> is required", http.StatusBadRequest)
			return
		}
		limit := 0
		if v := r.URL.Query().Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
				return
			}
			limit = min(n, 1000)
		}
		out, err := s.BackendThroughput(backend, limit)
		if err != nil {
			log.Printf("api: backend throughput: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func handleQueueSummary(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		summary, err := s.QueueSummary()
		if err != nil {
			log.Printf("api: queue summary: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, summary)
	}
}
