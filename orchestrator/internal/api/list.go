// SPDX-License-Identifier: Apache-2.0

package api

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// DefaultListLimit is GET /jobs's page size without ?limit=.
const DefaultListLimit = 50

// JobSummary is one GET /jobs row: identity, state and timing. The task and the answer stay on
// GET /jobs/{id}, so a full page is never hundreds of transcripts.
type JobSummary struct {
	RunID             string     `json:"run_id"`
	Seq               int64      `json:"seq"`
	AgentKey          string     `json:"agent_key"`
	State             string     `json:"state"`
	Priority          int        `json:"priority"`
	Shadow            bool       `json:"shadow"`
	Attempts          int        `json:"attempts"`
	CreatedAt         time.Time  `json:"created_at"`
	StartedAt         *time.Time `json:"started_at,omitempty"`
	FinishedAt        *time.Time `json:"finished_at,omitempty"`
	CloudFallbackUsed bool       `json:"cloud_fallback_used"`
	LocalBackendUsed  string     `json:"local_backend_used,omitempty"`
	SessionID         string     `json:"session_id,omitempty"`
	LegacySessionID   string     `json:"hermes_session_id,omitempty"`
	RetryOfRunID      string     `json:"retry_of_run_id,omitempty"`
	RetriedByRunID    string     `json:"retried_by_run_id,omitempty"`
	Resubmits         int        `json:"resubmits"`
	FailureClass      string     `json:"failure_class,omitempty"`
	// ProfileRevisionDrift: a retry that ran another profile revision than its parent.
	ProfileRevisionDrift bool `json:"profile_revision_drift,omitempty"`
}

// ListJobsResponse is GET /jobs's body. NextBeforeSeq is set when the page is full: pass it as
// ?before_seq= for the next, older page.
type ListJobsResponse struct {
	Jobs          []JobSummary `json:"jobs"`
	Limit         int          `json:"limit"`
	NextBeforeSeq int64        `json:"next_before_seq,omitempty"`
}

// sessionFilter is the session id a list asks for, under either name (LegacySessionField for the
// overlap release); a request that gives both with different values is refused.
func sessionFilter(r *http.Request) (string, bool) {
	q := r.URL.Query()
	if len(q["session_id"]) > 1 || len(q[LegacySessionField]) > 1 {
		return "", false
	}
	id, legacy := q.Get("session_id"), q.Get(LegacySessionField)
	if id != "" && legacy != "" && id != legacy {
		return "", false
	}
	if id == "" {
		id = legacy
	}
	return id, true
}

// handleListJobs serves GET /jobs?state=&agent=&session_id=&limit=&before_seq=, newest first by
// seq, so the order is stable and the cursor never skips or repeats a job. limit is 50 by
// default, at most store.MaxListLimit; an unknown state or a non-positive limit or cursor is a 400,
// never an empty or unbounded page.
func handleListJobs(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f := store.ListFilter{State: store.State(q.Get("state")), AgentKey: q.Get("agent"), Limit: DefaultListLimit}
		owner, restricted, allowed := listOwnerFilter(r.Context())
		if !allowed {
			http.Error(w, "no caller", http.StatusForbidden)
			return
		}
		if restricted {
			f.SubmittedBy = owner
		}
		if f.State != "" && !store.ValidState(f.State) {
			http.Error(w, "unknown state "+strconv.Quote(string(f.State)), http.StatusBadRequest)
			return
		}
		sid, ok := sessionFilter(r)
		if !ok {
			http.Error(w, "give one session id: session_id and "+LegacySessionField+" differ, or one is repeated", http.StatusBadRequest)
			return
		}
		f.SessionID = sid
		if v := q.Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
				return
			}
			f.Limit = min(n, store.MaxListLimit)
		}
		if v := q.Get("before_seq"); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 1 {
				http.Error(w, "before_seq must be a positive integer", http.StatusBadRequest)
				return
			}
			f.BeforeSeq = n
		}
		jobs, err := s.ListJobs(f)
		if err != nil {
			log.Printf("api: list jobs: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		out := ListJobsResponse{Jobs: make([]JobSummary, 0, len(jobs)), Limit: f.Limit}
		for _, j := range jobs {
			out.Jobs = append(out.Jobs, JobSummary{
				RunID: j.RunID, Seq: j.Seq, AgentKey: j.AgentKey, State: string(j.State), Priority: j.Priority,
				Shadow: j.Shadow, Attempts: j.Attempts, CreatedAt: j.CreatedAt, StartedAt: j.StartedAt,
				FinishedAt: j.FinishedAt, CloudFallbackUsed: j.CloudFallbackUsed, LocalBackendUsed: j.LocalBackendUsed,
				SessionID: j.SessionID, LegacySessionID: j.SessionID,
				RetryOfRunID: j.RetryOfRunID, RetriedByRunID: j.RetriedByRunID, Resubmits: j.Resubmits,
				FailureClass: j.FailureReason(), ProfileRevisionDrift: j.ProfileRevisionDrift(),
			})
		}
		if len(jobs) == f.Limit {
			out.NextBeforeSeq = jobs[len(jobs)-1].Seq
		}
		writeJSON(w, http.StatusOK, out)
	}
}
