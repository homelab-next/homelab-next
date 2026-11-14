// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/backends"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// slowReservePool widens the window between a pass reading its free slots and spending them.
type slowReservePool struct{ *countingPool }

func (s slowReservePool) Reserve(ctx context.Context, a backends.Affinity, runID, agentKey string) (string, bool) {
	time.Sleep(20 * time.Millisecond)
	return s.countingPool.Reserve(ctx, a, runID, agentKey)
}

// concurrencyRunner blocks every session until released and records the most running at once.
type concurrencyRunner struct {
	release chan struct{}
	now     atomic.Int32
	peak    atomic.Int32
}

func (c *concurrencyRunner) Run(ctx context.Context, s runner.Session) (*runner.Result, error) {
	n := c.now.Add(1)
	defer c.now.Add(-1)
	for {
		p := c.peak.Load()
		if n <= p || c.peak.CompareAndSwap(p, n) {
			break
		}
	}
	select {
	case <-c.release:
	case <-ctx.Done():
	}
	return &runner.Result{Response: "ok"}, nil
}

// Concurrency is a hard cap: overlapping passes never run more jobs than it, however their reads
// of the free slots interleave.
func TestTick_ConcurrencyIsAHardCapAcrossOverlappingPasses(t *testing.T) {
	cr := &concurrencyRunner{release: make(chan struct{})}
	r := newRig(t, rigOptions{runner: cr, concur: 2, backends: []backends.Backend{{Name: "engine-a"}, {Name: "engine-b"}, {Name: "engine-c"}}})
	cfg := r.cfg
	cfg.Pool = slowReservePool{r.pool}
	sch, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		r.submit(fmt.Sprintf("run-%d", i), defaultProfile)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sch.Tick(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	close(cr.release)
	wg.Wait()
	if p := cr.peak.Load(); p > 2 {
		t.Fatalf("%d jobs ran at once with a concurrency of 2", p)
	}
	r.pool.balanced(t)
}

// countingStore counts the queued-list reads.
type countingStore struct {
	*store.Store
	queuedReads atomic.Int32
}

func (c *countingStore) ListByState(s store.State) ([]*store.Job, error) {
	if s == store.StateQueued {
		c.queuedReads.Add(1)
	}
	return c.Store.ListByState(s)
}

func (c *countingStore) ListForAdmission(s store.State) ([]*store.Job, error) {
	if s == store.StateQueued {
		c.queuedReads.Add(1)
	}
	return c.Store.ListForAdmission(s)
}

// A pass reads the queued list once, however many jobs it holds: during an outage a long queue of
// held local-only jobs costs one read, not one per job.
func TestTick_ReadsTheQueueOncePerPass(t *testing.T) {
	h := newHealth(t)
	r := newRig(t, rigOptions{backends: []backends.Backend{{Name: "engine-a", HealthURL: h.URL}},
		profiles: map[string]string{defaultProfile: "local_only: true\n"}})
	h.ok.Store(false)
	probe(r)
	for i := 0; i < 200; i++ {
		j := &store.Job{RunID: fmt.Sprintf("r%04d", i), AgentKey: defaultProfile, Priority: 50, State: store.StateQueued,
			CreatedAt: time.Now().UTC(), TaskDescription: fmt.Sprintf("task %d", i), SubmittedBy: "alice"}
		if err := r.st.CreateJob(j); err != nil {
			t.Fatal(err)
		}
	}
	cs := &countingStore{Store: r.st}
	cfg := r.cfg
	cfg.Store = cs
	sch, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := sch.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := cs.queuedReads.Load(); n != 1 {
		t.Fatalf("the queued list was read %d times in one pass", n)
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("one pass over 200 held jobs took %s", el)
	}
}

// A held job is superseded only by a newer queued job of the same submitter and lane: another
// submitter's identical job, or the other lane's, never cancels it.
func TestSupersede_MatchesSubmitterAndLane(t *testing.T) {
	h := newHealth(t)
	r := newRig(t, rigOptions{backends: []backends.Backend{{Name: "engine-a", HealthURL: h.URL}},
		profiles: map[string]string{defaultProfile: "local_only: true\n"}})
	h.ok.Store(false)
	probe(r)
	mk := func(id, owner string, shadow bool) {
		j := &store.Job{RunID: id, AgentKey: defaultProfile, Priority: 50, State: store.StateQueued, CreatedAt: time.Now().UTC(),
			TaskDescription: "same task", SubmittedBy: owner, Shadow: shadow}
		if err := r.st.CreateJob(j); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	mk("alice-old", "alice", false)
	mk("bob-new", "bob", false)
	mk("alice-shadow-new", "alice", true)
	r.tick()
	for _, id := range []string{"alice-old", "bob-new", "alice-shadow-new"} {
		if j := r.job(id); j.State != store.StateQueued {
			t.Errorf("%s is %s: another submitter's or lane's job superseded it", id, j.State)
		}
	}
	mk("alice-new", "alice", false)
	r.tick()
	if j := r.job("alice-old"); j.State != store.StateCancelled {
		t.Errorf("alice's own newer job did not supersede her held one: %s", j.State)
	}
	r.sch.mu.Lock()
	_, kept := r.sch.waitCauses["alice-old"]
	r.sch.mu.Unlock()
	if kept {
		t.Error("the superseded job's wait cause was kept")
	}
}

// The wait causes of runs that left the queue without running (a cancel) are dropped by the next
// pass.
func TestWaitCauses_PrunedForRunsNoLongerQueued(t *testing.T) {
	r := newRig(t, rigOptions{})
	r.sch.noteWaitCause("gone", "slot")
	r.submit("queued", defaultProfile)
	r.tick()
	r.sch.mu.Lock()
	defer r.sch.mu.Unlock()
	if _, ok := r.sch.waitCauses["gone"]; ok {
		t.Error("a cause of a run no longer queued was kept")
	}
}

// fullRowsStore records a read of whole queued rows.
type fullRowsStore struct {
	*store.Store
	fullReads atomic.Int32
}

func (f *fullRowsStore) ListByState(s store.State) ([]*store.Job, error) {
	if s == store.StateQueued {
		f.fullReads.Add(1)
	}
	return f.Store.ListByState(s)
}

// A pass, and an automatic retry's duplicate check, read the queue without its text: never whole
// queued rows.
func TestTick_ReadsTheQueueWithoutItsText(t *testing.T) {
	r := newRig(t, rigOptions{runner: runnertestFail()})
	fs := &fullRowsStore{Store: r.st}
	cfg := r.cfg
	cfg.Store = fs
	sch, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.submit("run-1", defaultProfile)
	if err := sch.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := fs.fullReads.Load(); n != 0 {
		t.Fatalf("whole queued rows were read %d times", n)
	}
}
