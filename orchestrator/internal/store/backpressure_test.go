// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func shadowJob(id, agent string) *Job {
	j := queued(id, agent)
	j.Shadow = true
	return j
}

// An unfinished shadow job (queued, admitted, running or awaiting inference) blocks the agent's
// next one; a finished one does not. Production jobs and other agents are never blocked.
func TestShadowBackpressure_StatesAndIsolation(t *testing.T) {
	for _, state := range AllStates {
		t.Run(string(state), func(t *testing.T) {
			s := openTest(t)
			if err := s.CreateJob(shadowJob("first", "agent-a")); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(`UPDATE jobs SET state = ? WHERE run_id = 'first'`, string(state)); err != nil {
				t.Fatal(err)
			}
			active := state == StateQueued || state == StateAdmitted || state == StateRunning || state == StateAwaitingInference
			err := s.CreateJob(shadowJob("second", "agent-a"))
			if active {
				if !errors.Is(err, ErrShadowBackpressure) {
					t.Fatalf("got %v, want back-pressure", err)
				}
				if _, err := s.GetJob("second"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("the refused job was stored: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if got, err := s.GetJob("first"); err != nil || got.State != state {
				t.Fatalf("the existing job changed: %+v, %v", got, err)
			}
			for i := range 3 {
				prod := shadowJob(fmt.Sprintf("prod-%d", i), "agent-a")
				prod.Shadow = false
				if err := s.CreateJob(prod); err != nil {
					t.Fatalf("production blocked: %v", err)
				}
			}
			if err := s.CreateJob(shadowJob("other", "agent-b")); err != nil {
				t.Fatalf("another agent blocked: %v", err)
			}
		})
	}
}

// Thirty concurrent shadow submits on two connections to one file: exactly one is accepted, a
// replay of it still finds it, and finishing it frees the slot.
func TestShadowBackpressure_ConcurrentConnectionsAndRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orch.db")
	lock, err := LockInstance(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	s1, err := OpenWith(path, Options{Lock: lock})
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	s2, err := OpenWith(path, Options{Lock: lock})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	const n = 30
	results := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i] = []*Store{s1, s2}[i%2].CreateJob(shadowJob(fmt.Sprintf("job-%d", i), "agent-a"))
		}()
	}
	close(start)
	wg.Wait()
	accepted := 0
	for _, err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, ErrShadowBackpressure) {
			t.Errorf("unexpected error: %v", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d, want 1", accepted)
	}
	jobs, err := s1.ListByState(StateQueued)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("queued = %v, %v", jobs, err)
	}
	if err := s2.CreateJob(shadowJob(jobs[0].RunID, "agent-a")); !errors.Is(err, ErrDuplicateIdempotencyKey) {
		t.Fatalf("replay: %v", err)
	}
	if err := s1.UpdateState(jobs[0].RunID, StateQueued, StateCancelled); err != nil {
		t.Fatal(err)
	}
	if err := s2.CreateJob(shadowJob("after-release", "agent-a")); err != nil {
		t.Fatalf("slot not released: %v", err)
	}
}
