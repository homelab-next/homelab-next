// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner/runnertest"
)

// countPauses replaces the pool's concurrency wait with a counter: no clock is read and nothing
// sleeps, so the tests decide nothing by timing.
func countPauses(p *Policy) *[]time.Duration {
	var waits []time.Duration
	p.sleep = func(ctx context.Context, d time.Duration) bool {
		waits = append(waits, d)
		return ctx.Err() == nil
	}
	return &waits
}

var limited = runnertest.Fail(runner.ConcurrencyLimited, "429 concurrency_limited")

// A leg the gateway refuses at its backend's cap waits and asks the same backend again: it never
// moves to the next backend, and the wait spends none of the parser retries.
func TestCall_AConcurrencyLimitWaitsOnTheSameBackend(t *testing.T) {
	r := runnertest.New(limited, limited, limited, runnertest.Answer("answer"))
	p, _ := newPool(r, Backend{Name: "a"}, Backend{Name: "b"})
	p.PrimaryFirst = true
	p.ConcurrencyWait = 3 * time.Second
	waits := countPauses(p)
	res, err := p.Call(context.Background(), session("run-1"), CloudFallback, noAffinity, "")
	if err != nil || res.Response != "answer" || res.LocalBackendUsed != "a" || res.UsedCloud {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if got := targets(r); !reflect.DeepEqual(got, []string{"a", "a", "a", "a"}) {
		t.Errorf("targets = %v, want a four times", got)
	}
	if !reflect.DeepEqual(*waits, []time.Duration{3 * time.Second, 3 * time.Second, 3 * time.Second}) {
		t.Errorf("waits = %v", *waits)
	}
	if res.LocalAttempts != 4 || len(res.Attempts) != 4 || res.Attempts[0].Class != runner.ConcurrencyLimited || res.Attempts[3].Failed {
		t.Errorf("trail = %+v (%d attempts)", res.Attempts, res.LocalAttempts)
	}
}

// Past ConcurrencyWaits the chain stops: a limit is never a reason to try another backend or the
// cloud, and the job's failure says it was the limit.
func TestCall_AConcurrencyLimitNeverFallsOver(t *testing.T) {
	r := runnertest.New(cloudAnswers(failsOn(map[string]runnertest.Step{"a": limited}, "b answer")))
	p, _ := newPool(r, Backend{Name: "a"}, Backend{Name: "b"})
	p.PrimaryFirst = true
	p.ConcurrencyWaits = 2
	waits := countPauses(p)
	res, err := p.Call(context.Background(), session("run-1"), CloudFallback, noAffinity, "")
	if !errors.Is(err, ErrConcurrencyLimited) || !errors.Is(err, runner.ConcurrencyLimited) {
		t.Fatalf("err = %v", err)
	}
	if got := targets(r); !reflect.DeepEqual(got, []string{"a", "a", "a"}) {
		t.Errorf("targets = %v, want a three times and nothing else", got)
	}
	if len(*waits) != 2 || res.UsedCloud || res.LocalClass != runner.ConcurrencyLimited || res.LocalFailedReason == "" {
		t.Errorf("waits = %d, res = %+v", len(*waits), res)
	}
	if IsBackendDown(err) || errors.Is(err, ErrNotAttributable) || attributable(err) {
		t.Errorf("a limit read as the backend's fault: %v", err)
	}
}

// The cloud leg, reached through the gateway too, waits the same way, each session with its own
// usage file.
func TestCall_TheCloudLegWaitsAtTheConcurrencyCap(t *testing.T) {
	cloud := 0
	step := func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		if !s.Target.Cloud {
			return runnertest.Fail(runner.BackendFault, "connection refused")(ctx, s)
		}
		cloud++
		if cloud == 1 {
			return limited(ctx, s)
		}
		return runnertest.Answer("cloud answer")(ctx, s)
	}
	r := runnertest.New(step)
	p, _ := newPool(r, Backend{Name: "a"})
	waits := countPauses(p)
	res, err := p.Call(context.Background(), session("run-1"), CloudFallback, noAffinity, "")
	if err != nil || !res.UsedCloud || res.Response != "cloud answer" || len(*waits) != 1 {
		t.Fatalf("res = %+v, err = %v, waits = %d", res, err, len(*waits))
	}
	ss := r.Sessions()
	if len(ss) != 3 || ss[1].UsagePath == ss[2].UsagePath {
		t.Errorf("sessions = %+v", ss)
	}
}

// A job whose context ends during the wait ends with the job's deadline, not another attempt.
func TestCall_AConcurrencyWaitEndsWithTheJob(t *testing.T) {
	r := runnertest.New(limited)
	p, _ := newPool(r, Backend{Name: "a"}, Backend{Name: "b"})
	ctx, cancel := context.WithCancel(context.Background())
	p.sleep = func(context.Context, time.Duration) bool { cancel(); return false }
	res, err := p.Call(ctx, session("run-1"), CloudFallback, noAffinity, "")
	if !errors.Is(err, ErrJobDeadline) || len(r.Sessions()) != 1 || res.UsedCloud {
		t.Fatalf("res = %+v, err = %v, sessions = %v", res, err, targets(r))
	}
}

// The default wait is real time, cut short by the job's context.
func TestPause_EndsWithTheContext(t *testing.T) {
	p := &Policy{ConcurrencyWait: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p.pause(ctx) {
		t.Fatal("a pause outlived its context")
	}
	if p.concurrencyWaits() != DefaultConcurrencyWaits {
		t.Fatal("ConcurrencyWaits 0 is the default")
	}
}
