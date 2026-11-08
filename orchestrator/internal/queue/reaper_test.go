// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/backends"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner/runnertest"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

func noReapGrace(t *testing.T) {
	prev := reservationReapGrace
	reservationReapGrace = 0
	t.Cleanup(func() { reservationReapGrace = prev })
}

// A run cancelled while running keeps its claim until its executor returns: its row is no longer
// in flight, but its session is, and the reaper must not give its slot to another job meanwhile.
func TestReaper_KeepsTheClaimOfARunStillExecuting(t *testing.T) {
	noReapGrace(t)
	release := make(chan struct{})
	started := make(chan struct{})
	block := signalled(started, runnertest.Block(release, "late", nil))
	run := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		if s.RunID == "run-1" {
			return block(ctx, s)
		}
		return &runner.Result{Response: "ok"}, nil
	})
	r := newRig(t, rigOptions{runner: run, concur: 2,
		backends: []backends.Backend{{Name: "engine-a", MaxConcurrent: 1}}})
	r.submit("run-1", defaultProfile)
	done := r.tickAsync(context.Background())
	waitClosed(t, started, "the session's start")
	// The row moves first (the API's cancel), the executor's context is not cancelled yet.
	if err := r.st.UpdateState("run-1", store.StateRunning, store.StateCancelled); err != nil {
		t.Fatal(err)
	}
	r.submit("run-2", defaultProfile)
	r.tick()
	if !r.policy.HoldsReservation("run-1") {
		t.Fatal("the reaper took the claim of a run whose session still runs")
	}
	if j := r.job("run-2"); j.State != store.StateQueued {
		t.Fatalf("run-2 is %s: it got the slot of a session still running", j.State)
	}
	close(release)
	waitClosed(t, done, "the cancelled run's executor")
	r.pool.balanced(t)
}

// requeueStore runs hook right after the running -> queued write of a backend-down requeue.
type requeueStore struct {
	*store.Store
	once sync.Once
	hook func()
}

func (q *requeueStore) UpdateState(runID string, from, to store.State) error {
	err := q.Store.UpdateState(runID, from, to)
	if err == nil && from == store.StateRunning && to == store.StateQueued {
		q.once.Do(q.hook)
	}
	return err
}

// A backend-down requeue gives its claim back before the row reads queued: a pass that admits the
// run again at once, under the same run id, keeps its new claim.
func TestBackendDownRequeue_ReleasesBeforeTheRowIsQueued(t *testing.T) {
	h := newHealth(t)
	var n atomic.Int32
	second := make(chan struct{})
	release := make(chan struct{})
	run := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		if n.Add(1) == 1 {
			h.ok.Store(false)
			return &runner.Result{}, runner.MarkAbsent(errors.New("connection refused"))
		}
		close(second)
		<-release
		return &runner.Result{Response: "ok"}, nil
	})
	r := newRig(t, rigOptions{runner: run, concur: 2, backends: []backends.Backend{{Name: "engine-a", HealthURL: h.URL}},
		profiles: map[string]string{defaultProfile: "local_only: true\n"}})
	rs := &requeueStore{Store: r.st}
	cfg := r.cfg
	cfg.Store = rs
	sch, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var again <-chan struct{}
	rs.hook = func() {
		// The backend is back and a pass admits the requeued run before its first executor has
		// returned.
		h.ok.Store(true)
		probe(r)
		ch := make(chan struct{})
		go func() { defer close(ch); _ = sch.Tick(context.Background()) }()
		again = ch
		select { // not t.Fatal: this runs on the executor's goroutine
		case <-second:
		case <-time.After(15 * time.Second):
			t.Error("the re-admitted session did not start in 15s")
		}
	}
	r.submit("run-1", defaultProfile)
	if err := sch.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !r.policy.HoldsReservation("run-1") {
		t.Fatal("the first executor's release dropped the re-admitted run's claim")
	}
	close(release)
	waitClosed(t, again, "the re-admitted run")
	if j := r.job("run-1"); j.State != store.StateDone {
		t.Fatalf("run-1 is %s", j.State)
	}
	r.pool.balanced(t)
}

// A requeue that loses its compare-and-swap (a cancel moved the row) counts nothing and uncounts
// nothing: the requeue count and the attempts are left as they were.
func TestBackendDownRequeue_ALostSwapChangesNothing(t *testing.T) {
	h := newHealth(t)
	var st *store.Store
	run := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		h.ok.Store(false)
		if err := st.UpdateState(s.RunID, store.StateRunning, store.StateCancelled); err != nil {
			return nil, err
		}
		return &runner.Result{}, runner.MarkAbsent(errors.New("connection refused"))
	})
	r := newRig(t, rigOptions{runner: run, backends: []backends.Backend{{Name: "engine-a", HealthURL: h.URL}},
		profiles: map[string]string{defaultProfile: "local_only: true\n"}})
	st = r.st
	r.submit("run-1", defaultProfile)
	r.tick()
	j := r.job("run-1")
	r.sch.mu.Lock()
	count := r.sch.requeues["run-1"]
	r.sch.mu.Unlock()
	if j.State != store.StateCancelled || j.Attempts != 1 || count != 0 {
		t.Fatalf("job %s attempts=%d requeues=%d: a lost requeue counted", j.State, j.Attempts, count)
	}
	r.pool.balanced(t)
}

// orderQueued is PickNext applied again and again: one sort gives the order repeated picks would.
func TestOrderQueued_MatchesRepeatedPickNext(t *testing.T) {
	now := time.Now()
	var jobs []*store.Job
	for i := 0; i < 40; i++ {
		jobs = append(jobs, &store.Job{RunID: string(rune('a'+i%26)) + string(rune('a'+i/26)), Seq: int64(100 - i),
			Priority: 1 + (i*37)%100, CreatedAt: now.Add(-time.Duration(i*311) * time.Second)})
	}
	order := orderQueued(jobs, now)
	rest := append([]*store.Job(nil), jobs...)
	for i := range order {
		next := PickNext(rest, now)
		if next != order[i] {
			t.Fatalf("position %d: orderQueued %s, PickNext %s", i, order[i].RunID, next.RunID)
		}
		for k, j := range rest {
			if j == next {
				rest = append(rest[:k], rest[k+1:]...)
				break
			}
		}
	}
}
