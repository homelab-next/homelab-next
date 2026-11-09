// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

func TestSubmit_PersistsAndReturnsJobID(t *testing.T) {
	a := newAPI(t, nil)
	code, ok, _ := a.submit("", map[string]any{"agent_key": "watcher", "priority": 10, "task_description": "check it", "shadow": true})
	if code != http.StatusCreated || len(ok.RunID) != 32 {
		t.Fatalf("submit = %d %+v", code, ok)
	}
	j, err := a.st.GetJob(ok.RunID)
	if err != nil || j.State != store.StateQueued || j.Priority != 10 || j.TaskDescription != "check it" || !j.Shadow {
		t.Fatalf("stored = %+v, %v", j, err)
	}
}

// A task left out stays empty (the scheduler applies the profile's default); a task given is
// kept as given.
func TestSubmit_TaskDescriptionKeptOrLeftEmpty(t *testing.T) {
	a := newAPI(t, nil)
	_, ok, _ := a.submit("", map[string]any{"agent_key": "watcher"})
	if j, _ := a.st.GetJob(ok.RunID); j.TaskDescription != "" || j.Priority != 50 {
		t.Fatalf("defaults: task %q priority %d", j.TaskDescription, j.Priority)
	}
}

// A replay with the same key answers 200 with the first run; the header form is the same key.
func TestSubmit_DuplicateIdempotencyKeyReturnsSameJobID(t *testing.T) {
	a := newAPI(t, nil)
	body := map[string]any{"agent_key": "watcher", "idempotency_key": "k-1"}
	code, first, _ := a.submit("", body)
	if code != http.StatusCreated {
		t.Fatal(code)
	}
	code, again, _ := a.submit("", body)
	if code != http.StatusOK || again.RunID != first.RunID {
		t.Fatalf("replay = %d %+v", code, again)
	}
	req, _ := http.NewRequest(http.MethodPost, a.srv.URL+"/jobs", strings.NewReader(`{"agent_key":"watcher"}`))
	req.Header.Set("Idempotency-Key", "k-1")
	resp, err := a.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("header replay = %d", resp.StatusCode)
	}
	if code, _ := a.do(http.MethodPost, "/jobs", "", map[string]any{"agent_key": "watcher", "idempotency_key": strings.Repeat("k", store.MaxIdempotencyKeyLen+1)}); code != http.StatusBadRequest {
		t.Fatalf("an over-long key = %d", code)
	}
}

func TestSubmit_PriorityOutOfRangeReturns400(t *testing.T) {
	a := newAPI(t, nil)
	for _, p := range []int{-1, 101} {
		if code, _, _ := a.submit("", map[string]any{"agent_key": "watcher", "priority": p}); code != http.StatusBadRequest {
			t.Errorf("priority %d = %d", p, code)
		}
	}
}

// An unknown agent key is a 404 before anything is stored, a resubmit's included.
func TestSubmit_UnknownAgentKey(t *testing.T) {
	a := newAPI(t, nil)
	a.failed("p-1", "retired", store.FailureCapacity, "")
	for name, body := range map[string]map[string]any{
		"submit":   {"agent_key": "nobody"},
		"resubmit": {"agent_key": "retired", "retry_of_run_id": "p-1"},
	} {
		if code, _, _ := a.submit("", body); code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", name, code)
		}
	}
	if jobs, _ := a.st.ListJobs(store.ListFilter{Limit: 10}); len(jobs) != 1 {
		t.Fatalf("%d jobs stored, want only the parent", len(jobs))
	}
	if retried, _ := a.st.RetriedBy("p-1"); retried != "" {
		t.Fatalf("the parent was retried by %q", retried)
	}
}

// What the controller does not take is refused, never dropped: structured input, a passthrough
// request body.
func TestSubmit_InputAndRequestBodyAreRefusedNotDropped(t *testing.T) {
	a := newAPI(t, nil)
	for field, reason := range map[string]string{"input": "input_unsupported", "request_body": "request_body_unsupported"} {
		code, _, bad := a.submit("", map[string]any{"agent_key": "watcher", field: map[string]any{"x": 1}})
		if code != http.StatusBadRequest || bad.Reason != reason {
			t.Errorf("%s = %d %+v", field, code, bad)
		}
	}
	if code, _, _ := a.submit("", map[string]any{"agent_key": "watcher", "input": nil}); code != http.StatusCreated {
		t.Errorf("a null input = %d", code)
	}
}

// The submit body and the task are bounded.
func TestSubmit_SizeCaps(t *testing.T) {
	a := newAPI(t, nil)
	if code, _, _ := a.submit("", map[string]any{"agent_key": "watcher", "task_description": strings.Repeat("t", MaxTaskBytes+1)}); code != http.StatusRequestEntityTooLarge {
		t.Errorf("an oversized task = %d", code)
	}
	if code, _ := a.do(http.MethodPost, "/jobs", "", `{"agent_key":"watcher","profile_id":"`+strings.Repeat("p", MaxSubmitBytes)+`"}`); code != http.StatusRequestEntityTooLarge {
		t.Errorf("an oversized body = %d", code)
	}
	if code, _ := a.do(http.MethodPost, "/jobs", "", `{"agent_key":`); code != http.StatusBadRequest {
		t.Errorf("a malformed body = %d", code)
	}
	if jobs, _ := a.st.ListJobs(store.ListFilter{Limit: 10}); len(jobs) != 0 {
		t.Fatalf("%d jobs stored", len(jobs))
	}
}

func TestSubmit_ShadowBackpressure(t *testing.T) {
	a := newAPI(t, nil)
	if code, _, _ := a.submit("", map[string]any{"agent_key": "watcher", "shadow": true}); code != http.StatusCreated {
		t.Fatal(code)
	}
	if code, _, _ := a.submit("", map[string]any{"agent_key": "watcher", "shadow": true}); code != http.StatusTooManyRequests {
		t.Fatalf("a second shadow = %d", code)
	}
	if code, _, _ := a.submit("", map[string]any{"agent_key": "watcher"}); code != http.StatusCreated {
		t.Fatal("a real-lane job was held back")
	}
}

func TestGetJob_UnknownIDReturns404(t *testing.T) {
	if code, _ := newAPI(t, nil).getJob("", "nope"); code != http.StatusNotFound {
		t.Fatal(code)
	}
}

// GET /jobs/{id} reports the attempts, always, and the session id under both names for the
// overlap release.
func TestGetJob_ReportsAttemptsAndServesSessionIDUnderBothNames(t *testing.T) {
	a := newAPI(t, nil)
	_, ok, _ := a.submit("", map[string]any{"agent_key": "watcher"})
	_, out := a.do(http.MethodGet, "/jobs/"+ok.RunID, "", nil)
	if !strings.Contains(string(out), `"attempts":0`) {
		t.Fatalf("attempts missing: %s", out)
	}
	if err := a.st.UpdateAttempts(ok.RunID, 2); err != nil {
		t.Fatal(err)
	}
	if err := a.st.UpdateUsageFields(ok.RunID, store.UsageFields{SessionID: "sess-7"}); err != nil {
		t.Fatal(err)
	}
	_, out = a.do(http.MethodGet, "/jobs/"+ok.RunID, "", nil)
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["attempts"] != 2.0 || raw["session_id"] != "sess-7" || raw[LegacySessionField] != "sess-7" {
		t.Fatalf("job = %s", out)
	}
}

func TestCancel_QueuedJobTransitionsToCancelled(t *testing.T) {
	a := newAPI(t, nil)
	_, ok, _ := a.submit("", map[string]any{"agent_key": "watcher"})
	if code, _ := a.do(http.MethodPost, "/jobs/"+ok.RunID+"/cancel", "", nil); code != http.StatusOK {
		t.Fatal(code)
	}
	if j, _ := a.st.GetJob(ok.RunID); j.State != store.StateCancelled {
		t.Fatal(j.State)
	}
	if code, _ := a.do(http.MethodPost, "/jobs/"+ok.RunID+"/cancel", "", nil); code != http.StatusConflict {
		t.Fatalf("cancelling a cancelled job = %d", code)
	}
	if code, _ := a.do(http.MethodPost, "/jobs/nope/cancel", "", nil); code != http.StatusNotFound {
		t.Fatalf("cancelling nothing = %d", code)
	}
}

// A cancel moves the row, then stops the live session; with no live executor it emits the
// finished record itself.
func TestCancelRunning_NoLiveExecutorEmitsFinishedNow(t *testing.T) {
	var cancelled []string
	a := newAPI(t, func(c *Config) {
		c.CancelRun = func(id string) bool { cancelled = append(cancelled, id); return false }
	})
	a.st.EnableOutbox(func(j *store.Job) []store.OutboxEvent {
		if j.State == store.StateCancelled {
			return []store.OutboxEvent{{ID: "finished:" + j.RunID, Body: []byte(`{}`)}}
		}
		return nil
	}, 0, nil)
	if err := a.st.CreateJob(&store.Job{RunID: "r-1", AgentKey: "watcher", Priority: 50, State: store.StateRunning, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if code, _ := a.do(http.MethodPost, "/jobs/r-1/cancel", "", nil); code != http.StatusOK {
		t.Fatal(code)
	}
	recs, _ := a.st.PendingEvents(10)
	if len(cancelled) != 1 || len(recs) != 1 || recs[0].ID != "finished:r-1" {
		t.Fatalf("cancelRun calls %v, events %v", cancelled, recs)
	}
}

func TestReloadProfiles(t *testing.T) {
	if code, _ := newAPI(t, nil).do(http.MethodPost, "/admin/reload-profiles", "", nil); code != http.StatusNotImplemented {
		t.Fatalf("nil reload = %d", code)
	}
	calls := 0
	a := newAPI(t, func(c *Config) { c.ReloadProfiles = func() error { calls++; return nil } })
	if code, _ := a.do(http.MethodPost, "/admin/reload-profiles", "", nil); code != http.StatusOK || calls != 1 {
		t.Fatalf("reload = %d, %d calls", code, calls)
	}
	b := newAPI(t, func(c *Config) {
		c.ReloadProfiles = func() error { return errors.New("profiles/watcher.yaml: SECRET-DETAIL") }
	})
	code, out := b.do(http.MethodPost, "/admin/reload-profiles", "", nil)
	if code != http.StatusInternalServerError || strings.Contains(string(out), "SECRET-DETAIL") {
		t.Fatalf("a failed reload = %d %q: the error's text goes to the log, not the response", code, out)
	}
}

func TestBackendStatus(t *testing.T) {
	if code, _ := newAPI(t, nil).do(http.MethodGet, "/admin/backend-status", "", nil); code != http.StatusNotImplemented {
		t.Fatalf("nil = %d", code)
	}
	a := newAPI(t, func(c *Config) {
		c.BackendStatus = func(context.Context) ([]byte, error) { return []byte(`{"engines":[1]}`), nil }
	})
	if code, out := a.do(http.MethodGet, "/admin/backend-status", "", nil); code != http.StatusOK || string(out) != `{"engines":[1]}` {
		t.Fatalf("status = %d %s", code, out)
	}
	b := newAPI(t, func(c *Config) {
		c.BackendStatus = func(context.Context) ([]byte, error) { return nil, errors.New("exit 2") }
	})
	if code, _ := b.do(http.MethodGet, "/admin/backend-status", "", nil); code != http.StatusInternalServerError {
		t.Fatalf("failure = %d", code)
	}
}

func TestBackendEligibility(t *testing.T) {
	if code, _ := newAPI(t, nil).do(http.MethodGet, "/admin/backend-eligibility?backend=a", "", nil); code != http.StatusNotImplemented {
		t.Fatalf("nil = %d", code)
	}
	a := newAPI(t, func(c *Config) {
		c.BackendEligibility = func(b string) ([]BackendEligibilityEntry, error) {
			if b != "engine-a" {
				return nil, errors.New("unknown")
			}
			return []BackendEligibilityEntry{{AgentKey: "watcher", Eligible: false, Reason: "missing tag"}}, nil
		}
	})
	if code, _ := a.do(http.MethodGet, "/admin/backend-eligibility", "", nil); code != http.StatusBadRequest {
		t.Fatalf("no backend = %d", code)
	}
	if code, _ := a.do(http.MethodGet, "/admin/backend-eligibility?backend=engine-z", "", nil); code != http.StatusNotFound {
		t.Fatalf("unknown backend = %d", code)
	}
	code, out := a.do(http.MethodGet, "/admin/backend-eligibility?backend=engine-a", "", nil)
	var got []BackendEligibilityEntry
	if code != http.StatusOK || json.Unmarshal(out, &got) != nil || len(got) != 1 || got[0].Reason != "missing tag" {
		t.Fatalf("eligibility = %d %s", code, out)
	}
}

func TestBackendThroughputAndQueueSummary(t *testing.T) {
	a := newAPI(t, nil)
	if code, _ := a.do(http.MethodGet, "/admin/backend-throughput", "", nil); code != http.StatusBadRequest {
		t.Fatalf("no backend = %d", code)
	}
	if code, _ := a.do(http.MethodGet, "/admin/backend-throughput?backend=a&limit=0", "", nil); code != http.StatusBadRequest {
		t.Fatalf("limit 0 = %d", code)
	}
	code, out := a.do(http.MethodGet, "/admin/backend-throughput?backend=engine-a", "", nil)
	if code != http.StatusOK || !strings.Contains(string(out), `"sample_count":0`) {
		t.Fatalf("no samples = %d %s", code, out)
	}
	a.submit("", map[string]any{"agent_key": "watcher"})
	code, out = a.do(http.MethodGet, "/admin/queue-summary", "", nil)
	if code != http.StatusOK || !strings.Contains(string(out), "queued") {
		t.Fatalf("summary = %d %s", code, out)
	}
}

func TestBackendDrainRoutes(t *testing.T) {
	var got []string
	a := newAPI(t, func(c *Config) {
		c.BackendDrain = func(name string, drain bool) (any, error) {
			if name == "nope" {
				return nil, ErrBackendNotFound
			}
			if name == "broken" {
				return nil, errors.New("SECRET-DB-ERROR")
			}
			got = append(got, name+map[bool]string{true: "+", false: "-"}[drain])
			return map[string]any{"backend": name, "drained": drain}, nil
		}
	})
	if code, out := a.do(http.MethodPost, "/admin/backends/engine-a/drain", "", nil); code != http.StatusOK || !strings.Contains(string(out), `"drained":true`) {
		t.Fatalf("drain = %d %s", code, out)
	}
	if code, _ := a.do(http.MethodPost, "/admin/backends/engine-a/undrain", "", nil); code != http.StatusOK {
		t.Fatalf("undrain = %d", code)
	}
	if code, _ := a.do(http.MethodPost, "/admin/backends/nope/drain", "", nil); code != http.StatusNotFound {
		t.Fatalf("unknown = %d", code)
	}
	if code, out := a.do(http.MethodPost, "/admin/backends/broken/drain", "", nil); code != http.StatusInternalServerError || strings.Contains(string(out), "SECRET") {
		t.Fatalf("broken = %d %s", code, out)
	}
	if strings.Join(got, ",") != "engine-a+,engine-a-" {
		t.Fatalf("calls %v", got)
	}
	if code, _ := newAPI(t, nil).do(http.MethodPost, "/admin/backends/engine-a/drain", "", nil); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
		t.Fatalf("without the option the route exists: %d", code)
	}
}

func TestMetricsRoute(t *testing.T) {
	a := newAPI(t, func(c *Config) {
		c.Metrics = func(w io.Writer) error { _, err := io.WriteString(w, "hnx_orchestrator_up 1\n"); return err }
	})
	code, out := a.do(http.MethodGet, "/metrics", "", nil)
	if code != http.StatusOK || string(out) != "hnx_orchestrator_up 1\n" {
		t.Fatalf("metrics = %d %q", code, out)
	}
	b := newAPI(t, func(c *Config) { c.Metrics = func(io.Writer) error { return errors.New("x") } })
	if code, _ := b.do(http.MethodGet, "/metrics", "", nil); code != http.StatusInternalServerError {
		t.Fatalf("a failed scrape = %d", code)
	}
}

// GET /jobs pages newest first with a stable cursor, filters by state, agent and session id
// (under either name), and refuses an unknown state, a bad limit or cursor, and two session ids.
func TestListJobs(t *testing.T) {
	a := newAPI(t, nil)
	var ids []string
	for i := 0; i < 5; i++ {
		agent := "watcher"
		if i%2 == 1 {
			agent = "collector"
		}
		_, ok, _ := a.submit("", map[string]any{"agent_key": agent, "task_description": "SECRET-TASK"})
		ids = append(ids, ok.RunID)
	}
	if err := a.st.UpdateUsageFields(ids[2], store.UsageFields{SessionID: "sess-2"}); err != nil {
		t.Fatal(err)
	}
	list := func(q string) (int, ListJobsResponse, string) {
		code, out := a.do(http.MethodGet, "/jobs"+q, "", nil)
		var r ListJobsResponse
		_ = json.Unmarshal(out, &r)
		return code, r, string(out)
	}
	_, page, raw := list("?limit=2")
	if len(page.Jobs) != 2 || page.Jobs[0].RunID != ids[4] || page.NextBeforeSeq == 0 || strings.Contains(raw, "SECRET-TASK") {
		t.Fatalf("first page = %s", raw)
	}
	_, next, _ := list("?limit=2&before_seq=" + itoa(page.NextBeforeSeq))
	if len(next.Jobs) != 2 || next.Jobs[0].RunID != ids[2] {
		t.Fatalf("second page = %+v", next)
	}
	if _, r, _ := list("?agent=collector"); len(r.Jobs) != 2 {
		t.Fatalf("agent filter = %+v", r)
	}
	if _, r, _ := list("?state=queued"); len(r.Jobs) != 5 {
		t.Fatalf("state filter = %d", len(r.Jobs))
	}
	for _, q := range []string{"?session_id=sess-2", "?" + LegacySessionField + "=sess-2", "?session_id=sess-2&" + LegacySessionField + "=sess-2"} {
		if _, r, _ := list(q); len(r.Jobs) != 1 || r.Jobs[0].RunID != ids[2] || r.Jobs[0].SessionID != "sess-2" || r.Jobs[0].LegacySessionID != "sess-2" {
			t.Errorf("%s = %+v", q, r)
		}
	}
	for _, q := range []string{"?state=lost", "?limit=0", "?limit=x", "?before_seq=0", "?session_id=a&" + LegacySessionField + "=b"} {
		if code, _, _ := list(q); code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", q, code)
		}
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

// A job's cost is reported only when a usage report gave one: a known zero is 0, an unknown cost
// is absent, never read as 0.
func TestGetJob_AnUnknownCostIsAbsentAndAZeroCostIsZero(t *testing.T) {
	a := newAPI(t, nil)
	_, unknown, _ := a.submit("", map[string]any{"agent_key": "watcher", "idempotency_key": "k-unknown"})
	_, zero, _ := a.submit("", map[string]any{"agent_key": "watcher", "idempotency_key": "k-zero"})
	free := 0.0
	if err := a.st.UpdateUsageFields(zero.RunID, store.UsageFields{CostUSD: &free}); err != nil {
		t.Fatal(err)
	}
	read := func(id string) map[string]any {
		_, out := a.do(http.MethodGet, "/jobs/"+id, "", nil)
		var raw map[string]any
		if err := json.Unmarshal(out, &raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, ok := read(unknown.RunID)["cost_usd"]; ok {
		t.Error("an unknown cost was reported")
	}
	if v, ok := read(zero.RunID)["cost_usd"]; !ok || v != 0.0 {
		t.Errorf("a known zero cost = %v, %v", v, ok)
	}
}
