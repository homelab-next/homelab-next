// SPDX-License-Identifier: Apache-2.0

package runnertest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
)

func TestRunner_ScriptRecordsAndRepeatsItsLastStep(t *testing.T) {
	r := New(Fail(runner.Stalled, "wedged"), Answer("done"))
	ctx := context.Background()
	if _, err := r.Run(ctx, runner.Session{RunID: "a"}); !errors.Is(err, runner.Stalled) || runner.ClassOf(err) != runner.Stalled {
		t.Fatalf("first = %v, want Stalled", err)
	}
	for i := 0; i < 2; i++ {
		res, err := r.Run(ctx, runner.Session{RunID: "b"})
		if err != nil || res.Response != "done" {
			t.Fatalf("step %d = %+v, %v", i+2, res, err)
		}
	}
	got := r.Sessions()
	if len(got) != 3 || got[0].RunID != "a" || got[2].RunID != "b" {
		t.Fatalf("sessions = %+v", got)
	}
	got[0].RunID = "changed"
	if r.Sessions()[0].RunID != "a" {
		t.Fatal("Sessions handed out its own slice")
	}
	if res, err := New().Run(ctx, runner.Session{}); err != nil || res.Response != "ok" {
		t.Fatalf("empty script = %+v, %v", res, err)
	}
}

func TestRunner_BlockReleasesOrIsKilled(t *testing.T) {
	release := make(chan struct{})
	killed := make(chan runner.Session, 1)
	r := New(Block(release, "late", func(s runner.Session) { killed <- s }))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := r.Run(ctx, runner.Session{RunID: "k"}); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, runner.KilledByController) {
			t.Fatalf("killed session err = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a cancelled session did not return")
	}
	if s := <-killed; s.RunID != "k" {
		t.Fatalf("kill hook got %+v", s)
	}
	close(release)
	if res, err := r.Run(context.Background(), runner.Session{}); err != nil || res.Response != "late" {
		t.Fatalf("released = %+v, %v", res, err)
	}
}

func TestOn_PicksByTarget(t *testing.T) {
	r := New(On(map[string]Step{"a": Fail(runner.BackendFault, "down"), "cloud": Answer("cloud")}, Answer("other")))
	ctx := context.Background()
	if _, err := r.Run(ctx, runner.Session{Target: runner.Target{Backend: "a"}}); !errors.Is(err, runner.BackendFault) {
		t.Fatalf("a = %v", err)
	}
	if res, _ := r.Run(ctx, runner.Session{Target: runner.Target{Cloud: true, Backend: "a"}}); res.Response != "cloud" {
		t.Fatalf("cloud = %q", res.Response)
	}
	if res, _ := r.Run(ctx, runner.Session{Target: runner.Target{Backend: "b"}}); res.Response != "other" {
		t.Fatalf("b = %q", res.Response)
	}
}

func TestRunner_AnswerCheckAndConcurrentUse(t *testing.T) {
	r := New()
	if r.CheckAnswer("anything") != nil {
		t.Fatal("no AnswerCheck accepts every answer")
	}
	r.AnswerCheck = func(s string) error {
		if s == "context window exceeded" {
			return runner.Wrap(runner.ContextExceeded, errors.New(s))
		}
		return nil
	}
	if !errors.Is(r.CheckAnswer("context window exceeded"), runner.ContextExceeded) || r.CheckAnswer("fine") != nil {
		t.Fatal("AnswerCheck not applied")
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Run(context.Background(), runner.Session{}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := len(r.Sessions()); n != 16 {
		t.Fatalf("recorded %d sessions, want 16", n)
	}
}
