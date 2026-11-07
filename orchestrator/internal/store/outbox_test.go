// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/events"
)

func testBuilder(j *Job) []OutboxEvent {
	return []OutboxEvent{{ID: j.RunID + ":" + string(j.State), Body: fmt.Appendf(nil, `{"run":%q,"state":%q,"retried_by":%q}`, j.RunID, j.State, j.RetriedByRunID)}}
}

func pendingIDs(t *testing.T, s *Store) string {
	t.Helper()
	rows, err := s.PendingEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	return fmt.Sprint(ids)
}

// Lifecycle transitions enqueue their event in the same transaction, a lost compare-and-swap
// enqueues nothing, the outbox survives a restart, and a queued cancel publishes its terminal
// event but never a start.
func TestOutbox_TransitionsEnqueueDurably(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orch.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	nudged := 0
	s.EnableOutbox(testBuilder, 0, func() { nudged++ })
	mkJob(t, s, "r1", "agent-a", StateQueued)
	mkJob(t, s, "r2", "agent-a", StateQueued)
	for _, tr := range [][2]State{{StateQueued, StateAdmitted}, {StateAdmitted, StateRunning}, {StateRunning, StateFailed}} {
		if err := s.UpdateState("r1", tr[0], tr[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpdateState("r2", StateQueued, StateCancelled); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateState("r1", StateRunning, StateDone); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("CAS: %v", err)
	}
	want := "[r1:running r1:failed r2:cancelled]"
	if got := pendingIDs(t, s); got != want || nudged != 3 {
		t.Fatalf("outbox = %s (nudged %d), want %s (3)", got, nudged, want)
	}
	if n, _ := s.OutboxLen(); n != 3 {
		t.Errorf("OutboxLen = %d", n)
	}
	s.Close()
	s, _ = Open(path)
	defer s.Close()
	if got := pendingIDs(t, s); got != want {
		t.Fatalf("after restart = %s, want %s", got, want)
	}
	rows, _ := s.PendingEvents(1)
	if err := s.MarkEventAttempt(rows[0].Seq); err != nil {
		t.Fatal(err)
	}
	if rows, _ := s.PendingEvents(1); rows[0].Attempts != 1 {
		t.Errorf("attempts = %d", rows[0].Attempts)
	}
	if err := s.AckEvent(rows[0].Seq); err != nil {
		t.Fatal(err)
	}
	if got := pendingIDs(t, s); got != "[r1:failed r2:cancelled]" {
		t.Errorf("after ack: %s", got)
	}
}

// A full outbox drops and counts its oldest events; a duplicate id is not a new event.
func TestOutbox_BoundDropsOldest(t *testing.T) {
	s := openTest(t)
	if err := s.EnqueueEvent("e0", []byte("{}")); err == nil {
		t.Error("EnqueueEvent before EnableOutbox was accepted")
	}
	s.EnableOutbox(testBuilder, 2, nil)
	for _, id := range []string{"e1", "e2", "e3", "e2"} {
		if err := s.EnqueueEvent(id, []byte("{}")); err != nil {
			t.Fatal(err)
		}
	}
	if got := pendingIDs(t, s); got != "[e2 e3]" || s.OutboxDropped() != 1 {
		t.Errorf("outbox = %s, dropped %d; want [e2 e3] and 1", got, s.OutboxDropped())
	}
}

// Startup reconciliation enqueues each failed orphan's event in its own transaction.
func TestOutbox_ReconcileOrphansEnqueues(t *testing.T) {
	s := openTest(t)
	mkJob(t, s, "run", "agent-a", StateRunning)
	mkJob(t, s, "adm", "agent-a", StateAdmitted)
	mkJob(t, s, "ai", "agent-a", StateAwaitingInference)
	s.EnableOutbox(testBuilder, 0, nil)
	req, failed, err := s.ReconcileOrphans()
	if err != nil || req != 1 || failed != 2 {
		t.Fatalf("ReconcileOrphans = %d, %d, %v", req, failed, err)
	}
	if got := pendingIDs(t, s); got != "[run:failed ai:failed]" {
		t.Errorf("outbox = %s", got)
	}
}

// FailOrphan fails only a row still in `from`, keeps a reason the run had recorded, and
// enqueues the event.
func TestFailOrphan(t *testing.T) {
	s := openTest(t)
	mkJob(t, s, "r1", "agent-a", StateRunning)
	mkJob(t, s, "r2", "agent-a", StateRunning)
	if err := s.UpdateExecutionResult("r2", false, 1, "turn failed", ""); err != nil {
		t.Fatal(err)
	}
	s.EnableOutbox(testBuilder, 0, nil)
	if err := s.FailOrphan("r1", StateAdmitted, OrphanFailedReason); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("wrong from: %v", err)
	}
	for _, id := range []string{"r1", "r2"} {
		if err := s.FailOrphan(id, StateRunning, OrphanFailedReason); err != nil {
			t.Fatal(err)
		}
	}
	j1, _ := s.GetJob("r1")
	j2, _ := s.GetJob("r2")
	if j1.State != StateFailed || j1.LocalFailedReason != OrphanFailedReason || j1.FailureClass != FailureUnknown {
		t.Errorf("r1 = %s %q %q", j1.State, j1.LocalFailedReason, j1.FailureClass)
	}
	if j2.LocalFailedReason != "turn failed; "+OrphanFailedReason {
		t.Errorf("r2 reason = %q", j2.LocalFailedReason)
	}
	if got := pendingIDs(t, s); got != "[r1:failed r2:failed]" {
		t.Errorf("outbox = %s", got)
	}
}

// A cancel of a running run defers its finished record until the executor's last write; it is
// emitted once, by EmitDeferredFinished or, after a crash, by startup reconciliation.
func TestOutbox_DeferredFinished(t *testing.T) {
	s := openTest(t)
	mkJob(t, s, "c1", "agent-a", StateRunning)
	mkJob(t, s, "c2", "agent-a", StateRunning)
	nudged := 0
	s.EnableOutbox(testBuilder, 0, nil)
	s.SetOutboxNotify(func() { nudged++ })
	for _, id := range []string{"c1", "c2"} {
		if err := s.UpdateState(id, StateRunning, StateCancelled); err != nil {
			t.Fatal(err)
		}
	}
	if got := pendingIDs(t, s); got != "[]" {
		t.Fatalf("a cancel from running enqueued at once: %s", got)
	}
	if ids, err := s.DeferredFinishedPending(); err != nil || fmt.Sprint(ids) != "[c1 c2]" {
		t.Fatalf("pending = %v, %v", ids, err)
	}
	if err := s.UpdateTelemetry("c1", "engine-a", TokenCounts{OutputTokens: intp(42)}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.EmitDeferredFinished("c1"); err != nil {
			t.Fatal(err)
		}
	}
	if got := pendingIDs(t, s); got != "[c1:cancelled]" || nudged != 1 {
		t.Fatalf("outbox = %s (nudged %d), want one record", got, nudged)
	}
	if _, _, err := s.ReconcileOrphans(); err != nil {
		t.Fatal(err)
	}
	if got := pendingIDs(t, s); got != "[c1:cancelled c2:cancelled]" {
		t.Errorf("after reconciliation = %s", got)
	}
	if ids, _ := s.DeferredFinishedPending(); len(ids) != 0 {
		t.Errorf("still pending: %v", ids)
	}
	plain := openTest(t)
	if err := plain.EmitDeferredFinished("c1"); err != nil {
		t.Errorf("without an outbox: %v", err)
	}
}

// The failed event of a run the scheduler retries already names the retry: both are committed
// before the event is built.
func TestOutbox_FailWithRetryEventNamesTheRetry(t *testing.T) {
	s := openTest(t)
	mkJob(t, s, "p", "agent-a", StateRunning)
	s.EnableOutbox(testBuilder, 0, nil)
	retry := &Job{RunID: "p-r", AgentKey: "agent-a", Priority: 50, State: StateQueued, CreatedAt: time.Now().UTC(), RetryOfRunID: "p"}
	if ok, rerr, err := s.FailWithRetry("p", StateRunning, FailureCapacity, retry); !ok || rerr != nil || err != nil {
		t.Fatal(ok, rerr, err)
	}
	rows, _ := s.PendingEvents(10)
	if len(rows) != 1 || string(rows[0].Body) != `{"run":"p","state":"failed","retried_by":"p-r"}` {
		t.Errorf("events = %v", rows)
	}
}

// The store is the events sender's outbox: what a transition enqueues is delivered to a
// forwarder and acknowledged.
func TestOutbox_DrainedByTheEventsSender(t *testing.T) {
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, r.Header.Get(events.IdempotencyHdr)+"="+string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	s := openTest(t)
	s.EnableOutbox(testBuilder, 0, nil)
	sender, err := events.NewOutboxSender(events.Config{URL: srv.URL}, s, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sender.Close(ctx)
	}()
	s.SetOutboxNotify(sender.Nudge)
	mkJob(t, s, "r", "agent-a", StateAdmitted)
	if err := s.UpdateState("r", StateAdmitted, StateRunning); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n, _ := s.OutboxLen(); n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the sender did not drain the store's outbox")
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != `r:running={"run":"r","state":"running","retried_by":""}` {
		t.Errorf("forwarder got %v", got)
	}
}
