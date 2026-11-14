// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"sync"
	"testing"

	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// retryBody is what an automated retrier sends for a failed run.
func retryBody(parent, idem, reason string) map[string]any {
	return map[string]any{"agent_key": "watcher", "retry_of_run_id": parent, "idempotency_key": idem, "priority": 90, "reason": reason}
}

// A retryable failure is resubmitted once: the child replays the parent's task, and a replay of
// the same request answers the same child.
func TestResubmit_AcceptedOnceForARetryableFailure(t *testing.T) {
	a := newAPI(t, nil)
	a.failed("p-1", "watcher", store.FailureCapacity, "")
	code, ok, bad := a.submit("", retryBody("p-1", "evt-1", "capacity"))
	if code != http.StatusCreated || ok.RetryOfRunID != "p-1" {
		t.Fatalf("resubmit = %d %+v %+v", code, ok, bad)
	}
	child, _ := a.st.GetJob(ok.RunID)
	if child.TaskDescription != "the parent's task" || child.Resubmits != 1 || child.Priority != 90 {
		t.Fatalf("child = %+v", child)
	}
	if code, again, _ := a.submit("", retryBody("p-1", "evt-1", "capacity")); code != http.StatusOK || again.RunID != ok.RunID {
		t.Fatalf("replay = %d %+v", code, again)
	}
	code, _, bad = a.submit("", retryBody("p-1", "evt-2", "capacity"))
	if code != http.StatusConflict || bad.Reason != store.RefuseAlreadyRetried || bad.RetriedByRunID != ok.RunID {
		t.Fatalf("a second resubmit = %d %+v", code, bad)
	}
}

// Every refusal says why, machine-readably.
func TestResubmit_RefusalsAreMachineReadable(t *testing.T) {
	a := newAPI(t, nil)
	a.failed("p-handler", "watcher", store.FailureHandlerError, "")
	a.failed("p-stall", "watcher", store.FailureStall, "")
	a.failed("p-other", "collector", store.FailureStall, "")
	_, _, _ = a.submit("", map[string]any{"agent_key": "watcher", "idempotency_key": "queued-1"})
	for name, c := range map[string]struct {
		body   map[string]any
		status int
		reason string
	}{
		"unknown run":   {retryBody("nope", "e1", ""), http.StatusNotFound, store.RefuseUnknownRun},
		"not retryable": {retryBody("p-handler", "e2", ""), http.StatusUnprocessableEntity, store.RefuseNotRetryable},
		"wrong reason":  {retryBody("p-stall", "e3", "capacity"), http.StatusUnprocessableEntity, store.RefuseReasonMismatch},
		"other agent":   {retryBody("p-other", "e4", ""), http.StatusUnprocessableEntity, store.RefuseAgentKeyMismatch},
		"own task":      {map[string]any{"agent_key": "watcher", "retry_of_run_id": "p-stall", "task_description": "mine"}, http.StatusUnprocessableEntity, store.RefusePayloadOverride},
		"reason alone":  {map[string]any{"agent_key": "watcher", "reason": "stall"}, http.StatusBadRequest, "reason_without_retry"},
	} {
		code, _, bad := a.submit("", c.body)
		if code != c.status || bad.Reason != c.reason {
			t.Errorf("%s = %d %+v, want %d %s", name, code, bad, c.status, c.reason)
		}
	}
}

// Another caller's run is a 404, exactly like none.
func TestResubmit_OtherCallersRunIs404(t *testing.T) {
	a := newAPI(t, func(c *Config) { c.Auth = tokens(t, map[string][]string{"alice": {"jobs"}, "bob": {"jobs"}}) })
	a.failed("alices", "watcher", store.FailureStall, "alice")
	code, _, bad := a.submit("tok-bob", retryBody("alices", "e1", "stall"))
	if code != http.StatusNotFound || bad.Reason != store.RefuseUnknownRun {
		t.Fatalf("bob's resubmit of alice's run = %d %+v", code, bad)
	}
}

// Concurrent resubmits of one run: exactly one is created.
func TestResubmit_ConcurrentPostsOnlyOneWins(t *testing.T) {
	a := newAPI(t, nil)
	a.failed("p-1", "watcher", store.FailureTimeout, "")
	var mu sync.Mutex
	codes := map[int]int{}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, _ := a.do(http.MethodPost, "/jobs", "", retryBody("p-1", "", ""))
			mu.Lock()
			codes[code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[http.StatusCreated] != 1 || codes[http.StatusConflict] != 11 {
		t.Fatalf("codes = %v", codes)
	}
}

// A key reused for a different submit is a 422, never another job's run id.
func TestSubmit_IdempotencyKeyReplayForADifferentRunIs422(t *testing.T) {
	a := newAPI(t, nil)
	a.failed("p-1", "watcher", store.FailureStall, "")
	a.failed("p-2", "watcher", store.FailureStall, "")
	if code, _, _ := a.submit("", retryBody("p-1", "shared", "")); code != http.StatusCreated {
		t.Fatal(code)
	}
	if code, _, _ := a.submit("", map[string]any{"agent_key": "watcher", "idempotency_key": "plain"}); code != http.StatusCreated {
		t.Fatal(code)
	}
	for _, c := range []struct {
		name string
		body map[string]any
		want int
	}{
		{"another parent", retryBody("p-2", "shared", ""), http.StatusUnprocessableEntity},
		{"a plain submit", map[string]any{"agent_key": "watcher", "idempotency_key": "shared"}, http.StatusUnprocessableEntity},
		{"another lane", map[string]any{"agent_key": "watcher", "idempotency_key": "plain", "shadow": true}, http.StatusUnprocessableEntity},
		{"another agent", map[string]any{"agent_key": "collector", "idempotency_key": "plain"}, http.StatusUnprocessableEntity},
		{"the same submit", map[string]any{"agent_key": "watcher", "idempotency_key": "plain"}, http.StatusOK},
	} {
		code, _, bad := a.submit("", c.body)
		if code != c.want || (c.want == http.StatusUnprocessableEntity && bad.Reason != "idempotency_key_mismatch") {
			t.Errorf("%s = %d %+v", c.name, code, bad)
		}
	}
}

// An admin's resubmit of a caller's run is stored under the run's owner; the admin's own replay
// of it is answered from the owner's keys, and the owner sees the child.
func TestResubmit_AdminResubmitKeepsTheOwnerAndReplaysUnderIt(t *testing.T) {
	a := newAPI(t, func(c *Config) { c.Auth = tokens(t, map[string][]string{"alice": {"jobs"}, "ops": {"admin"}}) })
	a.failed("alices", "watcher", store.FailureStall, "alice")
	code, ok, _ := a.submit("tok-ops", retryBody("alices", "e1", "stall"))
	if code != http.StatusCreated {
		t.Fatalf("admin resubmit = %d", code)
	}
	if j, _ := a.st.GetJob(ok.RunID); j.SubmittedBy != "alice" {
		t.Fatalf("child owner = %q, want the parent's", j.SubmittedBy)
	}
	if code, again, _ := a.submit("tok-ops", retryBody("alices", "e1", "stall")); code != http.StatusOK || again.RunID != ok.RunID {
		t.Fatalf("the admin's replay = %d %+v, want 200 with the child", code, again)
	}
	if code, _, bad := a.submit("tok-alice", retryBody("alices", "e2", "stall")); code != http.StatusConflict || bad.RetriedByRunID != ok.RunID {
		t.Fatalf("the owner's own resubmit = %d %+v", code, bad)
	}
	if code, _ := a.getJob("tok-alice", ok.RunID); code != http.StatusOK {
		t.Fatalf("the owner reads the child: %d", code)
	}
}

// A retry records its parent's profile revision, and GET says when it ran another.
func TestResubmit_ProfileRevisionDriftIsVisible(t *testing.T) {
	a := newAPI(t, nil)
	a.failed("p", "watcher", store.FailureTimeout, "")
	if err := a.st.UpdateProfileRevision("p", "rev-a"); err != nil {
		t.Fatal(err)
	}
	_, ok, _ := a.submit("", retryBody("p", "e", ""))
	if err := a.st.UpdateProfileRevision(ok.RunID, "rev-b"); err != nil {
		t.Fatal(err)
	}
	_, j := a.getJob("", ok.RunID)
	if j.ParentProfileRevision != "rev-a" || j.ProfileRevision != "rev-b" || !j.ProfileRevisionDrift {
		t.Fatalf("job = %+v", j)
	}
}
