// SPDX-License-Identifier: Apache-2.0

package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// failedRun creates a run owned by owner and drives it queued -> admitted -> running -> to, with
// class (the scheduler's failing transition).
func failedRun(t *testing.T, s *Store, runID, owner string, to State, class string) {
	t.Helper()
	j := &Job{RunID: runID, AgentKey: "triage", Priority: 50, State: StateQueued, CreatedAt: time.Now().UTC(),
		TaskDescription: "task of " + runID, ProfileID: "p1", SubmittedBy: owner}
	if err := s.CreateJob(j); err != nil {
		t.Fatal(err)
	}
	for _, step := range [][2]State{{StateQueued, StateAdmitted}, {StateAdmitted, StateRunning}} {
		if err := s.UpdateState(runID, step[0], step[1]); err != nil {
			t.Fatal(err)
		}
	}
	if to == StateRunning {
		return
	}
	if err := s.UpdateStateClass(runID, StateRunning, to, class); err != nil {
		t.Fatal(err)
	}
}

func resubmit(s *Store, parent, idem, caller string, check ResubmitCheck) (*Job, error) {
	j := &Job{RunID: fmt.Sprintf("re-%s-%d", idem, time.Now().UnixNano()), AgentKey: "triage", Priority: 90,
		State: StateQueued, CreatedAt: time.Now().UTC(), IdempotencyKey: idem, RetryOfRunID: parent, SubmittedBy: caller}
	return j, s.CreateResubmit(j, check)
}

func refusalOf(t *testing.T, err error) *ResubmitRefusal {
	t.Helper()
	var r *ResubmitRefusal
	if !errors.As(err, &r) {
		t.Fatalf("err = %v, want a *ResubmitRefusal", err)
	}
	return r
}

// A run failed by its environment is resubmitted: the retry replays its task and profile, keeps
// the caller's priority, belongs to the parent's owner, and the parent names it.
func TestCreateResubmit_ReplaysTheParent(t *testing.T) {
	for _, class := range []string{FailureCapacity, FailureStall, FailureTimeout, FailureBackendDown} {
		t.Run(class, func(t *testing.T) {
			s := openTest(t)
			failedRun(t, s, "p", "alice", StateFailed, class)
			if err := s.UpdateProfileRevision("p", "rev-1"); err != nil {
				t.Fatal(err)
			}
			j, err := resubmit(s, "p", "evt-1", "admin", ResubmitCheck{Reason: class})
			if err != nil {
				t.Fatalf("CreateResubmit: %v", err)
			}
			got, _ := s.GetJob(j.RunID)
			if got.RetryOfRunID != "p" || got.Resubmits != 1 || got.TaskDescription != "task of p" || got.ProfileID != "p1" ||
				got.Priority != 90 || got.SubmittedBy != "alice" || got.ParentProfileRevision != "rev-1" {
				t.Errorf("retry = %+v", got)
			}
			if got.ProfileRevisionDrift() {
				t.Error("drift before the retry resolved a profile")
			}
			_ = s.UpdateProfileRevision(j.RunID, "rev-2")
			if got, _ = s.GetJob(j.RunID); !got.ProfileRevisionDrift() {
				t.Error("no drift reported for rev-1 -> rev-2")
			}
			parent, _ := s.GetJob("p")
			if parent.RetriedByRunID != j.RunID || parent.Resubmits != 0 || parent.FailureReason() != class {
				t.Errorf("parent = retried by %q, resubmits %d, class %q", parent.RetriedByRunID, parent.Resubmits, parent.FailureReason())
			}
			if by, _ := s.RetriedBy("p"); by != j.RunID {
				t.Errorf("RetriedBy = %q", by)
			}
		})
	}
}

func TestCreateResubmit_Refusals(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(t *testing.T, s *Store)
		parent string
		job    func(j *Job)
		check  ResubmitCheck
		kind   string
		reason string
	}{
		{name: "unknown run", parent: "nope", kind: RefusalNotFound, reason: RefuseUnknownRun},
		{name: "another caller's run", setup: func(t *testing.T, s *Store) { failedRun(t, s, "p", "bob", StateFailed, FailureCapacity) }, parent: "p",
			check: ResubmitCheck{MayAccess: func(owner string) bool { return owner == "alice" }}, kind: RefusalNotFound, reason: RefuseUnknownRun},
		{name: "agent_key mismatch", setup: func(t *testing.T, s *Store) { failedRun(t, s, "p", "", StateFailed, FailureCapacity) }, parent: "p",
			job: func(j *Job) { j.AgentKey = "other" }, kind: RefusalUnprocessable, reason: RefuseAgentKeyMismatch},
		{name: "still running", setup: func(t *testing.T, s *Store) { failedRun(t, s, "p", "", StateRunning, "") }, parent: "p", kind: RefusalUnprocessable, reason: RefuseNotFailed},
		{name: "done", setup: func(t *testing.T, s *Store) { failedRun(t, s, "p", "", StateDone, "") }, parent: "p", kind: RefusalUnprocessable, reason: RefuseNotFailed},
		{name: "cancelled", setup: func(t *testing.T, s *Store) { failedRun(t, s, "p", "", StateCancelled, "") }, parent: "p", kind: RefusalUnprocessable, reason: RefuseNotRetryable},
		{name: "budget_killed", setup: func(t *testing.T, s *Store) { failedRun(t, s, "p", "", StateBudgetKilled, "") }, parent: "p", kind: RefusalUnprocessable, reason: RefuseNotRetryable},
		{name: "deadline", setup: func(t *testing.T, s *Store) { failedRun(t, s, "p", "", StateFailed, FailureDeadline) }, parent: "p", kind: RefusalUnprocessable, reason: RefuseNotRetryable},
		{name: "turn cap", setup: func(t *testing.T, s *Store) { failedRun(t, s, "p", "", StateFailed, FailureTurnCap) }, parent: "p", kind: RefusalUnprocessable, reason: RefuseNotRetryable},
		{name: "budget class", setup: func(t *testing.T, s *Store) { failedRun(t, s, "p", "", StateFailed, FailureBudget) }, parent: "p", kind: RefusalUnprocessable, reason: RefuseNotRetryable},
		{name: "handler error", setup: func(t *testing.T, s *Store) { failedRun(t, s, "p", "", StateFailed, FailureHandlerError) }, parent: "p", kind: RefusalUnprocessable, reason: RefuseNotRetryable},
		{name: "no class recorded", setup: func(t *testing.T, s *Store) { failedRun(t, s, "p", "", StateFailed, "") }, parent: "p", kind: RefusalUnprocessable, reason: RefuseNotRetryable},
		{name: "reason mismatch", setup: func(t *testing.T, s *Store) { failedRun(t, s, "p", "", StateFailed, FailureStall) }, parent: "p",
			check: ResubmitCheck{Reason: FailureCapacity}, kind: RefusalUnprocessable, reason: RefuseReasonMismatch},
		{name: "own task", setup: func(t *testing.T, s *Store) { failedRun(t, s, "p", "", StateFailed, FailureCapacity) }, parent: "p",
			job: func(j *Job) { j.TaskDescription = "something else" }, kind: RefusalUnprocessable, reason: RefusePayloadOverride},
		{name: "own profile", setup: func(t *testing.T, s *Store) { failedRun(t, s, "p", "", StateFailed, FailureCapacity) }, parent: "p",
			job: func(j *Job) { j.ProfileID = "p2" }, kind: RefusalUnprocessable, reason: RefusePayloadOverride},
		{name: "shadow lane switch", setup: func(t *testing.T, s *Store) { failedRun(t, s, "p", "", StateFailed, FailureCapacity) }, parent: "p",
			job: func(j *Job) { j.Shadow = true }, kind: RefusalUnprocessable, reason: RefusePayloadOverride},
		{name: "retry of a retry", setup: func(t *testing.T, s *Store) {
			failedRun(t, s, "p", "", StateFailed, FailureCapacity)
			c := &Job{RunID: "c", AgentKey: "triage", Priority: 90, State: StateQueued, CreatedAt: time.Now().UTC(), RetryOfRunID: "p"}
			if err := s.CreateResubmit(c, ResubmitCheck{}); err != nil {
				t.Fatal(err)
			}
			for _, tr := range [][2]State{{StateQueued, StateAdmitted}, {StateAdmitted, StateRunning}} {
				if err := s.UpdateState("c", tr[0], tr[1]); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.UpdateStateClass("c", StateRunning, StateFailed, FailureCapacity); err != nil {
				t.Fatal(err)
			}
		}, parent: "c", kind: RefusalConflict, reason: RefuseRetryChainSpent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := openTest(t)
			if tc.setup != nil {
				tc.setup(t, s)
			}
			j := &Job{RunID: "new", AgentKey: "triage", Priority: 90, State: StateQueued, CreatedAt: time.Now().UTC(), RetryOfRunID: tc.parent}
			if tc.job != nil {
				tc.job(j)
			}
			r := refusalOf(t, s.CreateResubmit(j, tc.check))
			if r.Kind != tc.kind || r.Reason != tc.reason {
				t.Errorf("refusal = %s/%s (%s), want %s/%s", r.Kind, r.Reason, r.Detail, tc.kind, tc.reason)
			}
			if _, err := s.GetJob("new"); !errors.Is(err, ErrNotFound) {
				t.Errorf("a refused resubmit created a job (%v)", err)
			}
		})
	}
	if err := openTest(t).CreateResubmit(queued("x", "triage"), ResubmitCheck{}); err == nil {
		t.Error("CreateResubmit without RetryOfRunID was accepted")
	}
}

// A run the scheduler already retried has had its one retry: a caller's resubmit is
// already_retried, naming it, and the scheduler cannot add a second either.
func TestCreateResubmit_AfterTheSchedulersRetry(t *testing.T) {
	s := openTest(t)
	failedRun(t, s, "p", "", StateFailed, FailureCapacity)
	auto := &Job{RunID: "auto", AgentKey: "triage", Priority: 50, State: StateQueued, CreatedAt: time.Now().UTC(), RetryOfRunID: "p"}
	if err := s.CreateJob(auto); err != nil {
		t.Fatal(err)
	}
	_, err := resubmit(s, "p", "evt-1", "", ResubmitCheck{})
	if r := refusalOf(t, err); r.Kind != RefusalConflict || r.Reason != RefuseAlreadyRetried || r.RetriedByRunID != "auto" {
		t.Errorf("refusal = %+v, want conflict/already_retried by auto", r)
	}
	second := &Job{RunID: "auto2", AgentKey: "triage", Priority: 50, State: StateQueued, CreatedAt: time.Now().UTC(), RetryOfRunID: "p"}
	if r := refusalOf(t, s.CreateJob(second)); r.Reason != RefuseAlreadyRetried {
		t.Errorf("second scheduler retry: %+v", r)
	}
	// the scheduler may retry a run whose row is gone; still once
	orphan := &Job{RunID: "o1", AgentKey: "triage", Priority: 50, State: StateQueued, CreatedAt: time.Now().UTC(), RetryOfRunID: "gone"}
	if err := s.CreateJob(orphan); err != nil {
		t.Fatalf("scheduler retry of a missing parent: %v", err)
	}
	if j, _ := s.GetJob("o1"); j.Resubmits != 1 {
		t.Errorf("resubmits = %d, want 1", j.Resubmits)
	}
}

// A replayed resubmit (same idempotency key) finds its run instead of a 409.
func TestCreateResubmit_IdempotencyKeyComesFirst(t *testing.T) {
	s := openTest(t)
	failedRun(t, s, "p", "", StateFailed, FailureTimeout)
	if _, err := resubmit(s, "p", "evt-1", "", ResubmitCheck{}); err != nil {
		t.Fatal(err)
	}
	if _, err := resubmit(s, "p", "evt-1", "", ResubmitCheck{}); !errors.Is(err, ErrDuplicateIdempotencyKey) {
		t.Errorf("replay: %v, want ErrDuplicateIdempotencyKey", err)
	}
	_, err := resubmit(s, "p", "evt-2", "", ResubmitCheck{})
	if r := refusalOf(t, err); r.Reason != RefuseAlreadyRetried {
		t.Errorf("a new key: %+v, want already_retried", r)
	}
}

// Twenty concurrent resubmits of one run, each with its own key: exactly one is created.
func TestCreateResubmit_ConcurrentOnlyOneWins(t *testing.T) {
	s := openTest(t)
	failedRun(t, s, "p", "", StateFailed, FailureBackendDown)
	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = resubmit(s, "p", fmt.Sprintf("evt-%d", i), "", ResubmitCheck{})
		}()
	}
	close(start)
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		} else if r := refusalOf(t, err); r.Reason != RefuseAlreadyRetried {
			t.Errorf("loser: %+v", r)
		}
	}
	var count int
	s.db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE retry_of_run_id = 'p'`).Scan(&count)
	if ok != 1 || count != 1 {
		t.Fatalf("%d resubmits succeeded and %d rows retry p, want 1 and 1", ok, count)
	}
}

// The unique index is the last line of defence below the check in the transaction.
func TestRetryOfRunID_UniqueIndex(t *testing.T) {
	s := openTest(t)
	ins := `INSERT INTO jobs (run_id, agent_key, priority, seq, state, created_at, retry_of_run_id) VALUES (?, 'a', 1, ?, 'queued', '2026-01-01T00:00:00Z', 'p')`
	if _, err := s.db.Exec(ins, "c1", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ins, "c2", 2); err == nil {
		t.Fatal("a second row with the same retry_of_run_id was accepted")
	}
}

// A database that already holds two retries of one run still opens, migrated behind a backup
// (the index falls back to a plain one), and still refuses a third retry.
func TestOpen_DuplicateRetriesFromBeforeTheIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orch.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP INDEX idx_jobs_retry_of`); err != nil {
		t.Fatal(err)
	}
	ins := `INSERT INTO jobs (run_id, agent_key, priority, seq, state, created_at, retry_of_run_id) VALUES (?, 'a', 1, ?, 'failed', '2026-01-01T00:00:00Z', ?)`
	for i, row := range [][2]string{{"p", ""}, {"c1", "p"}, {"c2", "p"}} {
		if _, err := s.db.Exec(ins, row[0], i+1, nullIfEmpty(row[1])); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	if _, err := Open(path); !errors.Is(err, ErrBackupRequired) {
		t.Fatalf("reopen without a backup: %v, want ErrBackupRequired", err)
	}
	backup := filepath.Join(t.TempDir(), "orch.db.bak")
	if err := BackupForMigration(path, backup); err != nil {
		t.Fatal(err)
	}
	s, err = OpenWith(path, Options{MigrationBackup: backup})
	if err != nil {
		t.Fatalf("reopen with duplicate retries: %v", err)
	}
	defer s.Close()
	if c1, err := s.GetJob("c1"); err != nil || c1.Resubmits != 1 {
		t.Errorf("a retry from before the column = %+v, %v; want resubmits 1", c1, err)
	}
	third := &Job{RunID: "c3", AgentKey: "a", Priority: 1, State: StateQueued, CreatedAt: time.Now().UTC(), RetryOfRunID: "p"}
	if r := refusalOf(t, s.CreateJob(third)); r.Reason != RefuseAlreadyRetried {
		t.Errorf("third retry: %+v", r)
	}
	var name sql.NullString
	s.db.QueryRow(`SELECT name FROM sqlite_master WHERE name = ?`, retryOfFallbackIndex).Scan(&name)
	if !name.Valid {
		t.Error("no fallback index on retry_of_run_id")
	}
	s.Close()
	if s, err := Open(path); err != nil {
		t.Errorf("the fallback index counts as current, yet: %v", err)
	} else {
		s.Close()
	}
}

// FailWithRetry: the failing transition and the scheduler's retry commit together; a lost
// compare-and-swap creates no retry; a retry that cannot be created never keeps the run from
// failing.
func TestFailWithRetry(t *testing.T) {
	s := openTest(t)
	retryOf := func(parent, id string) *Job {
		return &Job{RunID: id, AgentKey: "triage", Priority: 50, State: StateQueued, CreatedAt: time.Now().UTC(), RetryOfRunID: parent}
	}
	failedRun(t, s, "a", "", StateRunning, "")
	retried, retryErr, err := s.FailWithRetry("a", StateRunning, FailureCapacity, retryOf("a", "a-r"))
	if !retried || retryErr != nil || err != nil {
		t.Fatalf("FailWithRetry = %v %v %v", retried, retryErr, err)
	}
	if j, _ := s.GetJob("a"); j.State != StateFailed || j.FailureClass != FailureCapacity || j.RetriedByRunID != "a-r" {
		t.Errorf("parent = %s/%s retried by %q", j.State, j.FailureClass, j.RetriedByRunID)
	}

	failedRun(t, s, "b", "", StateCancelled, "")
	if _, _, err := s.FailWithRetry("b", StateRunning, FailureCapacity, retryOf("b", "b-r")); !errors.Is(err, ErrStateConflict) {
		t.Errorf("lost CAS: %v, want ErrStateConflict", err)
	}
	if _, err := s.GetJob("b-r"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a lost CAS created the retry: %v", err)
	}

	failedRun(t, s, "c", "", StateRunning, "")
	if err := s.CreateJob(retryOf("c", "c-r1")); err != nil {
		t.Fatal(err)
	}
	retried, retryErr, err = s.FailWithRetry("c", StateRunning, FailureBackendDown, retryOf("c", "c-r2"))
	if retried || retryErr == nil || err != nil {
		t.Errorf("refused retry = %v %v %v, want false, a refusal, nil", retried, retryErr, err)
	}
	if j, _ := s.GetJob("c"); j.State != StateFailed || j.FailureClass != FailureBackendDown {
		t.Errorf("run with a refused retry = %s/%s", j.State, j.FailureClass)
	}

	failedRun(t, s, "d", "", StateRunning, "")
	if retried, _, err := s.FailWithRetry("d", StateRunning, FailureHandlerError, nil); retried || err != nil {
		t.Errorf("no retry asked: %v %v", retried, err)
	}
}
