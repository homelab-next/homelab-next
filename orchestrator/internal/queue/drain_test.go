// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner/runnertest"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// A stopping service refuses new work first: once admission ends no job is admitted, the job
// already running keeps running (its session is not killed), and RunAdmitting returns only when it
// has finished.
func TestRunAdmitting_StopsAdmittingAndKeepsRunningJobs(t *testing.T) {
	release := make(chan struct{})
	var killed atomic.Bool
	r := newRig(t, rigOptions{runner: runnertest.New(runnertest.Block(release, "done", func(runner.Session) { killed.Store(true) }))})
	r.submit("run-1", defaultProfile)
	admit, stopAdmitting := context.WithCancel(context.Background())
	jobs, cancelJobs := context.WithCancel(context.Background())
	defer cancelJobs()
	returned := make(chan struct{})
	go func() { defer close(returned); r.sch.RunAdmitting(admit, jobs, 50*time.Millisecond) }()
	r.waitState("run-1", store.StateRunning)
	r.submit("run-2", defaultProfile) // the one slot is taken: run-2 waits
	stopAdmitting()
	select {
	case <-returned:
		t.Fatal("RunAdmitting returned while a job it admitted was still running")
	default:
	}
	close(release)
	waitClosed(t, returned, "RunAdmitting")
	if killed.Load() {
		t.Fatal("stopping admission killed the running session")
	}
	if j := r.job("run-1"); j.State != store.StateDone {
		t.Fatalf("run-1 is %s", j.State)
	}
	if j := r.job("run-2"); j.State != store.StateQueued {
		t.Fatalf("run-2 is %s: it was admitted after admission stopped", j.State)
	}
	// The slot is free now, so only the stop keeps run-2 queued: a pass that runs after it (one
	// already under way when admission ended) admits nothing.
	if err := r.sch.tick(admit, jobs); err != nil {
		t.Fatal(err)
	}
	if j := r.job("run-2"); j.State != store.StateQueued {
		t.Fatalf("run-2 is %s: a pass after the stop admitted it into the free slot", j.State)
	}
	// and the same pass with admission on admits it: the slot really was free
	if err := r.sch.tick(context.Background(), jobs); err != nil {
		t.Fatal(err)
	}
	if j := r.job("run-2"); j.State != store.StateDone {
		t.Fatalf("run-2 is %s after a pass with admission on", j.State)
	}
}
