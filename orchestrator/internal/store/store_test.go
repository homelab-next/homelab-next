// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A new database is created, and the same file opened again (a restart) holds its jobs.
func TestOpen_CreatesSchemaAndSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orch.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	j := queued("run-1", "watcher")
	j.ProfileID, j.ProfileRevision = "watcher-v1", "rev-1"
	if err := s.CreateJob(j); err != nil {
		t.Fatal(err)
	}
	if j.Seq == 0 {
		t.Error("CreateJob assigned no Seq")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if steps, err := PendingMigrations(path); err != nil || len(steps) != 0 {
		t.Fatalf("a new database has pending migrations %v (%v)", steps, err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatalf("Open again: %v", err)
	}
	defer s.Close()
	got, err := s.GetJob("run-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.AgentKey != "watcher" || got.State != StateQueued || got.ProfileID != "watcher-v1" || got.Seq != j.Seq {
		t.Errorf("after restart: %+v", got)
	}
}

func TestOpen_RefusesSpecialPathCharacters(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "orch.db?mode=memory")); err == nil {
		t.Fatal("a path with '?' was accepted (SQLite would cut it short)")
	}
}

func TestCreateJob_SeqIsIncreasingAndNeverReused(t *testing.T) {
	s := openTest(t)
	var last int64
	for i := range 5 {
		j := queued(fmt.Sprintf("run-%d", i), "agent-a")
		if err := s.CreateJob(j); err != nil {
			t.Fatal(err)
		}
		if j.Seq <= last {
			t.Fatalf("seq %d after %d", j.Seq, last)
		}
		last = j.Seq
	}
}

// An idempotency key is never released: a replay is refused while its job is in flight and
// after it has finished, so it always finds its first run.
func TestCreateJob_IdempotencyKeyIsNeverReleased(t *testing.T) {
	s := openTest(t)
	first := queued("run-a", "agent-a")
	first.IdempotencyKey = "same-key"
	if err := s.CreateJob(first); err != nil {
		t.Fatal(err)
	}
	replay := func() error {
		j := queued(fmt.Sprintf("run-b-%d", time.Now().UnixNano()), "agent-a")
		j.IdempotencyKey = "same-key"
		return s.CreateJob(j)
	}
	if err := replay(); !errors.Is(err, ErrDuplicateIdempotencyKey) {
		t.Fatalf("replay: %v, want ErrDuplicateIdempotencyKey", err)
	}
	if err := s.UpdateState("run-a", StateQueued, StateCancelled); err != nil {
		t.Fatal(err)
	}
	if err := replay(); !errors.Is(err, ErrDuplicateIdempotencyKey) {
		t.Fatalf("replay after the first run ended: %v, want ErrDuplicateIdempotencyKey", err)
	}
	if all, _ := s.ListJobs(ListFilter{Limit: 10}); len(all) != 1 {
		t.Errorf("%d jobs, want 1", len(all))
	}
	// an empty key is no key: any number of jobs may have it
	for i := range 2 {
		j := queued(fmt.Sprintf("nokey-%d", i), "agent-a")
		j.IdempotencyKey = ""
		if err := s.CreateJob(j); err != nil {
			t.Fatalf("job without a key: %v", err)
		}
	}
}

func TestUpdateState_PersistsAndStampsTimes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orch.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateJob(queued("run-x", "agent-a")); err != nil {
		t.Fatal(err)
	}
	for _, tr := range [][2]State{{StateQueued, StateAdmitted}, {StateAdmitted, StateRunning}} {
		if err := s.UpdateState("run-x", tr[0], tr[1]); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	s, _ = Open(path)
	defer s.Close()
	j, err := s.GetJob("run-x")
	if err != nil || j.State != StateRunning || j.StartedAt == nil || j.FinishedAt != nil {
		t.Fatalf("after reopen: %+v, %v", j, err)
	}
	if err := s.UpdateStateClass("run-x", StateRunning, StateFailed, FailureStall); err != nil {
		t.Fatal(err)
	}
	j, _ = s.GetJob("run-x")
	if j.FinishedAt == nil || j.FailureClass != FailureStall || j.FailureReason() != FailureStall {
		t.Errorf("failed run: finished %v class %q", j.FinishedAt, j.FailureClass)
	}
	if _, err := s.GetJob("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetJob(missing) = %v", err)
	}
}

func TestListByState_ReturnsOnlyThatState(t *testing.T) {
	s := openTest(t)
	mkJob(t, s, "q1", "agent-a", StateQueued)
	mkJob(t, s, "r1", "agent-a", StateRunning)
	mkJob(t, s, "q2", "agent-b", StateQueued)
	got, err := s.ListByState(StateQueued)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].RunID != "q1" || got[1].RunID != "q2" {
		t.Errorf("ListByState(queued) = %v, want [q1 q2] in submission order", got)
	}
}

// Concurrent submits with distinct keys all succeed: every write transaction takes the write
// lock up front and waits for it, where a deferred one would fail with a stale snapshot.
func TestCreateJob_ConcurrentSubmitsAllSucceed(t *testing.T) {
	s := openTest(t)
	const n = 30
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.CreateJob(queued(fmt.Sprintf("c-%d", i), "agent-a"))
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("submit %d: %v", i, err)
		}
	}
	got, err := s.ListByState(StateQueued)
	if err != nil || len(got) != n {
		t.Fatalf("%d queued jobs (%v), want %d", len(got), err, n)
	}
	seen := map[int64]bool{}
	for _, j := range got {
		if seen[j.Seq] {
			t.Fatalf("seq %d assigned twice", j.Seq)
		}
		seen[j.Seq] = true
	}
}

// Two transitions racing from the same observed state: exactly one wins, the other gets
// ErrStateConflict, and the row holds the winner's state (a cancel is never overwritten by the
// executor's late done).
func TestUpdateState_CompareAndSwap(t *testing.T) {
	s := openTest(t)
	mkJob(t, s, "race", "agent-a", StateRunning)
	var wg sync.WaitGroup
	var cancelErr, doneErr error
	wg.Add(2)
	go func() { defer wg.Done(); cancelErr = s.UpdateState("race", StateRunning, StateCancelled) }()
	go func() { defer wg.Done(); doneErr = s.UpdateState("race", StateRunning, StateDone) }()
	wg.Wait()
	if (cancelErr == nil) == (doneErr == nil) {
		t.Fatalf("cancel %v, done %v: want exactly one to win", cancelErr, doneErr)
	}
	winner, loserErr := StateCancelled, doneErr
	if doneErr == nil {
		winner, loserErr = StateDone, cancelErr
	}
	if !errors.Is(loserErr, ErrStateConflict) {
		t.Errorf("loser: %v, want ErrStateConflict", loserErr)
	}
	if j, _ := s.GetJob("race"); j.State != winner {
		t.Errorf("state %s, want the winner's %s", j.State, winner)
	}
}

// Startup reconciliation: queued and terminal rows are untouched, admitted goes back to queued,
// running and awaiting_inference become failed with a finish time and the labelled reason (a
// reason the run had already recorded is kept), and the agent's shadow slot is free again.
func TestReconcileOrphans(t *testing.T) {
	s := openTest(t)
	mkJob(t, s, "o-queued", "agent-a", StateQueued)
	mkJob(t, s, "o-admitted", "agent-a", StateAdmitted)
	mkJob(t, s, "o-running", "agent-a", StateRunning)
	mkJob(t, s, "o-reasoned", "agent-a", StateRunning)
	mkJob(t, s, "o-done", "agent-a", StateDone)
	ai := queued("o-awaiting", "agent-s")
	ai.State, ai.Shadow = StateAwaitingInference, true
	if err := s.CreateJob(ai); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateExecutionResult("o-reasoned", false, 1, "turn failed", ""); err != nil {
		t.Fatal(err)
	}
	requeued, failed, err := s.ReconcileOrphans()
	if err != nil || requeued != 1 || failed != 3 {
		t.Fatalf("ReconcileOrphans = %d, %d, %v; want 1, 3", requeued, failed, err)
	}
	for id, want := range map[string]State{"o-queued": StateQueued, "o-admitted": StateQueued, "o-running": StateFailed,
		"o-reasoned": StateFailed, "o-done": StateDone, "o-awaiting": StateFailed} {
		if j, _ := s.GetJob(id); j.State != want {
			t.Errorf("%s: %s, want %s", id, j.State, want)
		}
	}
	for _, id := range []string{"o-running", "o-awaiting"} {
		j, _ := s.GetJob(id)
		if j.FinishedAt == nil || j.LocalFailedReason != ReconcileFailedReason || j.FailureReason() != FailureUnknown {
			t.Errorf("%s: finished %v reason %q class %q", id, j.FinishedAt, j.LocalFailedReason, j.FailureReason())
		}
	}
	if j, _ := s.GetJob("o-reasoned"); j.LocalFailedReason != "turn failed" {
		t.Errorf("a recorded reason was replaced: %q", j.LocalFailedReason)
	}
	next := queued("next", "agent-s")
	next.Shadow = true
	if err := s.CreateJob(next); err != nil {
		t.Errorf("shadow submit after reconciliation: %v", err)
	}
}

func TestCreateJob_TaskDescriptionRoundTrips(t *testing.T) {
	s := openTest(t)
	with := queued("with", "watcher")
	with.TaskDescription = "Check every service answers its health probe."
	if err := s.CreateJob(with); err != nil {
		t.Fatal(err)
	}
	mkJob(t, s, "without", "agent-a", StateQueued)
	if j, _ := s.GetJob("with"); j.TaskDescription != with.TaskDescription {
		t.Errorf("GetJob task = %q", j.TaskDescription)
	}
	if j, _ := s.GetJob("without"); j.TaskDescription != "" {
		t.Errorf("task = %q, want empty", j.TaskDescription)
	}
	list, _ := s.ListByState(StateQueued)
	if list[0].TaskDescription != with.TaskDescription {
		t.Errorf("ListByState task = %q", list[0].TaskDescription)
	}
}

// A revision is set after the job exists, and clearing it stores NULL, which reads back as "".
func TestUpdateProfileRevision(t *testing.T) {
	s := openTest(t)
	mkJob(t, s, "rev", "watcher", StateQueued)
	if j, _ := s.GetJob("rev"); j.ProfileRevision != "" {
		t.Errorf("revision before = %q", j.ProfileRevision)
	}
	if err := s.UpdateProfileRevision("rev", "abc123def456"); err != nil {
		t.Fatal(err)
	}
	if j, _ := s.GetJob("rev"); j.ProfileRevision != "abc123def456" {
		t.Errorf("revision = %q", j.ProfileRevision)
	}
	if err := s.UpdateProfileRevision("rev", ""); err != nil {
		t.Fatal(err)
	}
	j, err := s.GetJob("rev")
	if err != nil || j.ProfileRevision != "" {
		t.Errorf("after clearing: %v, %v", j, err)
	}
}

func TestUpdateExecutionResult(t *testing.T) {
	s := openTest(t)
	mkJob(t, s, "x", "agent-a", StateRunning)
	if err := s.UpdateExecutionResult("x", true, 2, "backend unreachable", "the report"); err != nil {
		t.Fatal(err)
	}
	j, _ := s.GetJob("x")
	if !j.CloudFallbackUsed || j.LocalAttempts != 2 || j.LocalFailedReason != "backend unreachable" || j.ResponseBody != "the report" {
		t.Errorf("execution result = %+v", j)
	}
	if err := s.UpdateExecutionResult("x", false, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if j, _ := s.GetJob("x"); j.ResponseBody != "" {
		t.Errorf("response body = %q, want empty", j.ResponseBody)
	}
}

func TestQueueSummary(t *testing.T) {
	s := openTest(t)
	older := time.Now().UTC().Add(-10 * time.Minute)
	newer := time.Now().UTC().Add(-time.Minute)
	for _, j := range []*Job{
		{RunID: "w-1", AgentKey: "watcher", State: StateQueued, CreatedAt: older},
		{RunID: "w-2", AgentKey: "watcher", State: StateQueued, CreatedAt: newer},
		{RunID: "w-3", AgentKey: "watcher", State: StateRunning, CreatedAt: newer},
		{RunID: "a-1", AgentKey: "agent-a", State: StateRunning, CreatedAt: newer},
		{RunID: "d-1", AgentKey: "watcher", State: StateDone, CreatedAt: newer},
	} {
		j.Priority = 50
		if err := s.CreateJob(j); err != nil {
			t.Fatal(err)
		}
	}
	sum, err := s.QueueSummary()
	if err != nil {
		t.Fatal(err)
	}
	if sum.ByState["queued"] != 2 || sum.ByState["running"] != 2 || sum.ByState["done"] != 1 {
		t.Errorf("ByState = %v", sum.ByState)
	}
	want := map[string]int{"watcher|queued": 2, "watcher|running": 1, "agent-a|running": 1}
	if len(sum.Active) != len(want) {
		t.Errorf("Active = %+v", sum.Active)
	}
	for _, e := range sum.Active {
		if want[e.AgentKey+"|"+e.State] != e.Count {
			t.Errorf("Active entry %+v", e)
		}
	}
	if sum.OldestQueuedRunID != "w-1" || sum.OldestQueuedAgeSeconds < 9*60 {
		t.Errorf("oldest queued = %q, %.0fs", sum.OldestQueuedRunID, sum.OldestQueuedAgeSeconds)
	}
	empty := openTest(t)
	if sum, err := empty.QueueSummary(); err != nil || sum.OldestQueuedRunID != "" || len(sum.ByState) != 0 {
		t.Errorf("empty queue summary = %+v, %v", sum, err)
	}
}

// The rate is sum(tokens) / sum(seconds) over the backend's done jobs, never an average of
// per-job rates, and another backend's jobs never enter it.
func TestBackendThroughput_IsAWeightedAverage(t *testing.T) {
	s := openTest(t)
	base := time.Now().UTC().Add(-time.Hour)
	mk := func(id, backend string, offset, dur time.Duration, tokens int) {
		mkJob(t, s, id, "agent-a", StateDone)
		start := base.Add(offset)
		if _, err := s.db.Exec(`UPDATE jobs SET started_at = ?, finished_at = ? WHERE run_id = ?`,
			start.Format(time.RFC3339Nano), start.Add(dur).Format(time.RFC3339Nano), id); err != nil {
			t.Fatal(err)
		}
		if err := s.UpdateTelemetry(id, backend, TokenCounts{InputTokens: intp(0), OutputTokens: intp(tokens), ReasoningTokens: intp(0), APICalls: intp(1)}); err != nil {
			t.Fatal(err)
		}
	}
	// 1 token/s and 990 tokens/s: the naive mean is 495.5, the real rate 10000/110
	mk("a-slow", "engine-a", 0, 100*time.Second, 100)
	mk("a-fast", "engine-a", 10*time.Minute, 10*time.Second, 9900)
	mk("b-any", "engine-b", 0, 5*time.Second, 999999)
	got, err := s.BackendThroughput("engine-a", 20)
	if err != nil {
		t.Fatal(err)
	}
	if got.SampleCount != 2 || got.TotalOutputTokens != 10000 || got.TotalDurationSecs != 110 || got.TokensPerSecond != 10000.0/110.0 {
		t.Errorf("throughput = %+v", got)
	}
	if got, err := s.BackendThroughput("engine-none", 0); err != nil || got.SampleCount != 0 || got.TokensPerSecond != 0 {
		t.Errorf("no samples = %+v, %v; want zero and no error", got, err)
	}
}

func TestUpdateTelemetry_RoundTripsAndKeepsUnknown(t *testing.T) {
	s := openTest(t)
	mkJob(t, s, "tel", "watcher", StateQueued)
	if j, _ := s.GetJob("tel"); j.LocalBackendUsed != "" || j.InputTokens != 0 || j.Usage.Known() {
		t.Errorf("before = %+v", j)
	}
	if err := s.UpdateTelemetry("tel", "engine-a", TokenCounts{InputTokens: intp(254287), OutputTokens: intp(12809), ReasoningTokens: intp(5313), APICalls: intp(19)}); err != nil {
		t.Fatal(err)
	}
	j, _ := s.GetJob("tel")
	if j.LocalBackendUsed != "engine-a" || j.InputTokens != 254287 || j.OutputTokens != 12809 || j.ReasoningTokens != 5313 || j.APICalls != 19 {
		t.Errorf("after = %+v", j)
	}
	if err := s.UpdateTelemetry("tel", "", TokenCounts{OutputTokens: intp(0)}); err != nil {
		t.Fatal(err)
	}
	j, _ = s.GetJob("tel")
	if j.Usage.InputTokens != nil || j.Usage.OutputTokens == nil || *j.Usage.OutputTokens != 0 {
		t.Errorf("unknown and zero must stay apart: %+v", j.Usage)
	}
}

func TestListJobs_FilterOrderAndCursor(t *testing.T) {
	s := openTest(t)
	for i := 1; i <= 7; i++ {
		agent := "agent-a"
		if i%2 == 0 {
			agent = "agent-b"
		}
		mkJob(t, s, fmt.Sprintf("r%d", i), agent, StateQueued)
	}
	if err := s.UpdateState("r3", StateQueued, StateCancelled); err != nil {
		t.Fatal(err)
	}
	ids := func(js []*Job) string {
		var out []string
		for _, j := range js {
			out = append(out, j.RunID)
		}
		return fmt.Sprint(out)
	}
	page, err := s.ListJobs(ListFilter{Limit: 3})
	if err != nil || ids(page) != "[r7 r6 r5]" {
		t.Fatalf("page 1 = %s, %v", ids(page), err)
	}
	if got, _ := s.ListJobs(ListFilter{Limit: 3, BeforeSeq: page[2].Seq}); ids(got) != "[r4 r3 r2]" {
		t.Errorf("page 2 = %s", ids(got))
	}
	if got, _ := s.ListJobs(ListFilter{AgentKey: "agent-a", State: StateQueued, Limit: 10}); ids(got) != "[r7 r5 r1]" {
		t.Errorf("agent-a queued = %s", ids(got))
	}
	if got, _ := s.ListJobs(ListFilter{State: StateCancelled}); ids(got) != "[r3]" {
		t.Errorf("cancelled (limit 0 is 1) = %s", ids(got))
	}
	if got, _ := s.ListJobs(ListFilter{Limit: 1 << 30}); len(got) != 7 {
		t.Errorf("a huge limit returned %d", len(got))
	}
}

func TestListJobs_SubmittedBy(t *testing.T) {
	s := openTest(t)
	for _, j := range []*Job{
		{RunID: "a1", AgentKey: "x", SubmittedBy: "alice"},
		{RunID: "b1", AgentKey: "x", SubmittedBy: "bob"},
		{RunID: "n1", AgentKey: "x"},
	} {
		j.Priority, j.State, j.CreatedAt = 50, StateQueued, time.Now().UTC()
		if err := s.CreateJob(j); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListJobs(ListFilter{SubmittedBy: "alice", Limit: 10})
	if err != nil || len(got) != 1 || got[0].RunID != "a1" || got[0].SubmittedBy != "alice" {
		t.Fatalf("ListJobs(alice) = %v, %v", got, err)
	}
	if j, _ := s.GetJob("n1"); j.SubmittedBy != "" {
		t.Errorf("unowned job SubmittedBy = %q", j.SubmittedBy)
	}
	if all, _ := s.ListJobs(ListFilter{Limit: 10}); len(all) != 3 {
		t.Errorf("unfiltered = %d jobs", len(all))
	}
}

// ListJobs filters by the runner's session id.
func TestListJobs_SessionID(t *testing.T) {
	s := openTest(t)
	for _, id := range []string{"a", "b"} {
		if err := s.CreateJob(queued(id, "x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpdateUsageFields("b", UsageFields{SessionID: "sess-b"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListJobs(ListFilter{SessionID: "sess-b", Limit: 10})
	if err != nil || len(got) != 1 || got[0].RunID != "b" || got[0].SessionID != "sess-b" {
		t.Fatalf("ListJobs(session) = %v, %v", got, err)
	}
}

// A drain survives a restart and keeps its first since.
func TestDrains_SaveLoadDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orch.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	since := time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC)
	if err := s.SaveDrain("engine-a", since); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDrain("engine-a", since.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, _ = Open(path)
	defer s.Close()
	got, err := s.LoadDrains()
	if err != nil || len(got) != 1 || !got["engine-a"].Equal(since) {
		t.Fatalf("LoadDrains = %v, %v", got, err)
	}
	if err := s.DeleteDrain("engine-a"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LoadDrains(); len(got) != 0 {
		t.Errorf("after delete: %v", got)
	}
}

// The admission list leaves out the text admission never reads, and keeps the rest.
func TestListForAdmission_LeavesOutTheText(t *testing.T) {
	s := openTest(t)
	j := queued("a", "x")
	j.TaskDescription = "the task"
	if err := s.CreateJob(j); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateExecutionResult("a", false, 1, "SECRET-REASON", "SECRET-ANSWER"); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListForAdmission(StateQueued)
	if err != nil || len(got) != 1 {
		t.Fatalf("ListForAdmission = %v, %v", got, err)
	}
	if g := got[0]; g.ResponseBody != "" || g.LocalFailedReason != "" || g.TaskDescription != "the task" || g.RunID != "a" || g.IdempotencyKey != "idem-a" {
		t.Fatalf("row = %+v", g)
	}
	if strings.Count(admissionColumns, "NULL") != 4 {
		t.Fatalf("columns = %s", admissionColumns)
	}
}
