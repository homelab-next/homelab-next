// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/inference"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner/runnertest"
)

var noAffinity = Affinity{}

func cloudAnswers(other runnertest.Step) runnertest.Step {
	return runnertest.On(map[string]runnertest.Step{"cloud": runnertest.Answer("cloud answer")}, other)
}

func failsOn(fails map[string]runnertest.Step, answer string) runnertest.Step {
	return runnertest.On(fails, runnertest.Answer(answer))
}

func targets(r *runnertest.Runner) []string {
	var out []string
	for _, s := range r.Sessions() {
		if s.Target.Cloud {
			out = append(out, "cloud")
		} else {
			out = append(out, s.Target.Backend)
		}
	}
	return out
}

func lockFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "backend.lock")
}

// Every session carries the run's identity and its own target, limits and leg usage path; the
// cloud leg has a home only.
func TestCall_EachSessionCarriesTheRunAndItsOwnLeg(t *testing.T) {
	r := runnertest.New(cloudAnswers(runnertest.Fail(runner.BackendFault, "it did not work")))
	p, _ := newPool(r, Backend{Name: "a", Home: "ha", Endpoint: "engine-a.example.internal:8000", LoadProbeURLs: []string{"u"}})
	p.Limits = runner.Limits{Timeout: time.Minute, StallTimeout: time.Second, MaxTurns: 7, Liveness: "progress"}
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if err != nil || !res.UsedCloud || res.Response != "cloud answer" || res.LocalFailedReason != "it did not work" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	got := r.Sessions()
	if len(got) != 2 {
		t.Fatalf("sessions = %d, want 2", len(got))
	}
	local, cloud := got[0], got[1]
	if local.RunID != "run-1" || local.AgentKey != "watcher" || local.Prompt != "p" || !reflect.DeepEqual(local.Toolsets, []string{"t"}) ||
		!reflect.DeepEqual(local.Target, runner.Target{Backend: "a", Home: "ha", Endpoint: "engine-a.example.internal:8000", ProbeURLs: []string{"u"}}) ||
		local.UsagePath != "/u/run-1.json" || local.Limits != p.Limits {
		t.Errorf("local session = %+v", local)
	}
	if !reflect.DeepEqual(cloud.Target, runner.Target{Cloud: true, Home: "cloud-home"}) || cloud.UsagePath != "/u/run-1.leg2.json" || cloud.Limits != p.Limits || cloud.RunID != "run-1" {
		t.Errorf("cloud session = %+v", cloud)
	}
}

// A local answer ends the chain; the trail says so.
func TestCall_ALocalAnswerNeverStartsTheCloudLeg(t *testing.T) {
	r := runnertest.New(failsOn(map[string]runnertest.Step{"cloud": runnertest.Fail(runner.Internal, "the cloud leg ran")}, "local answer"))
	p, _ := newPool(r, Backend{Name: "a", Home: "ha", NeedsInterlock: true})
	p.Interlock = inference.NewInterlock(lockFile(t), 10*time.Millisecond)
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if err != nil || res.Response != "local answer" || res.UsedCloud || res.LocalAttempts != 1 || res.LocalFailedReason != "" || res.LocalBackendUsed != "a" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if want := []Attempt{{Backend: "a"}}; !reflect.DeepEqual(res.Attempts, want) {
		t.Errorf("attempts = %+v, want %+v", res.Attempts, want)
	}
}

// Two local backends: the second is tried before the cloud leg is.
func TestCall_FailsOverToTheNextLocalBackendBeforeTheCloud(t *testing.T) {
	r := runnertest.New(failsOn(map[string]runnertest.Step{
		"first": runnertest.Fail(runner.BackendFault, "first unreachable"),
		"cloud": runnertest.Fail(runner.Internal, "the cloud leg ran"),
	}, "second answer"))
	p, _ := newPool(r, Backend{Name: "first", Home: "h1"}, Backend{Name: "second", Home: "h2", NeedsInterlock: true})
	p.Interlock = inference.NewInterlock(lockFile(t), 10*time.Millisecond)
	p.PrimaryFirst = true
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if err != nil || res.UsedCloud || res.LocalBackendUsed != "second" || res.LocalAttempts != 2 || res.Response != "second answer" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if got := targets(r); !reflect.DeepEqual(got, []string{"first", "second"}) {
		t.Errorf("targets = %v", got)
	}
}

// A second local attempt is unconditional: even a failure that is not the backend's moves on to the
// next local backend (it costs nothing a cloud leg would).
func TestCall_EveryLocalFailureMovesToTheNextLocalBackend(t *testing.T) {
	r := runnertest.New(failsOn(map[string]runnertest.Step{"first": runnertest.Fail(runner.Internal, "a bad flag")}, "second answer"))
	p, _ := newPool(r, Backend{Name: "first"}, Backend{Name: "second"})
	p.PrimaryFirst = true
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if err != nil || res.LocalBackendUsed != "second" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

// Every class that is the backend's (or a capacity gap the cloud leg does not have) reaches the
// cloud; the trail keeps the local leg's class.
func TestCall_EveryAttributableClassReachesTheCloud(t *testing.T) {
	for _, c := range []runner.Class{runner.BackendFault, runner.Stalled, runner.TimeoutCeiling, runner.TurnFailed, runner.ContextExceeded, runner.ToolCallParse} {
		t.Run(c.String(), func(t *testing.T) {
			r := runnertest.New(cloudAnswers(runnertest.Fail(c, "the leg failed")))
			p, _ := newPool(r, Backend{Name: "a"})
			res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
			if err != nil || !res.UsedCloud || res.Response != "cloud answer" || res.LocalClass != c || res.CloudClass != runner.Internal {
				t.Fatalf("res = %+v, err = %v", res, err)
			}
		})
	}
}

// A failure that is not the backend's never reaches the cloud, whatever its text says: the pool reads
// classes, not words.
func TestCall_AnUnattributableFailureNeverStartsTheCloudLeg(t *testing.T) {
	for name, step := range map[string]runnertest.Step{
		"no class, text reading like an outage": func(context.Context, runner.Session) (*runner.Result, error) {
			return &runner.Result{}, errors.New("dial tcp: connection refused; context deadline exceeded; timed out; No route to host")
		},
		"killed externally": runnertest.Fail(runner.KilledExternally, "signal: killed"),
		"absent hint, no probe to confirm it": func(context.Context, runner.Session) (*runner.Result, error) {
			return &runner.Result{}, runner.MarkAbsent(errors.New("nothing answered"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := runnertest.New(cloudAnswers(step))
			p, _ := newPool(r, Backend{Name: "a"})
			res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
			if !errors.Is(err, ErrNotAttributable) || res.UsedCloud || res.LocalAttempts != 1 || res.LocalFailedReason == "" || len(r.Sessions()) != 1 {
				t.Fatalf("res = %+v, err = %v, sessions = %v", res, err, targets(r))
			}
		})
	}
}

// Every class in a leg's error decides, not only its outermost: a runner wraps what it saw first
// under what ended the session. The shapes are the ones a subprocess runner builds (a failed turn or
// a kill around the class its output showed).
func TestCall_DecidesOnEveryClassInALeg(t *testing.T) {
	nest := func(outer, inner runner.Class) runnertest.Step {
		return func(context.Context, runner.Session) (*runner.Result, error) {
			return &runner.Result{}, runner.Wrap(outer, runner.Wrap(inner, errors.New("the leg failed")))
		}
	}
	threeWindows := []Backend{{Name: "small", MaxContext: 8}, {Name: "mid", MaxContext: 16}, {Name: "big", MaxContext: 64}}
	for _, c := range []struct {
		name     string
		backends []Backend
		failing  string
		step     runnertest.Step
		want     []string
		wantErr  error
	}{
		{"a failed turn around the turn cap stops the chain", []Backend{{Name: "a"}, {Name: "b"}}, "a", nest(runner.TurnFailed, runner.TurnCap), []string{"a"}, ErrTurnCapStops},
		{"a failed turn around a parser rejection retries the backend", []Backend{{Name: "a"}, {Name: "b"}}, "a", nest(runner.TurnFailed, runner.ToolCallParse), []string{"a", "a", "a", "b"}, nil},
		{"a fault around a parser rejection retries the backend", []Backend{{Name: "a"}, {Name: "b"}}, "a", nest(runner.BackendFault, runner.ToolCallParse), []string{"a", "a", "a", "b"}, nil},
		{"a failed turn around a context exhaustion goes biggest first", threeWindows, "small", nest(runner.TurnFailed, runner.ContextExceeded), []string{"small", "big"}, nil},
		{"an external kill around a fault reaches the cloud", []Backend{{Name: "a"}}, "a", nest(runner.KilledExternally, runner.BackendFault), []string{"a", "cloud"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := runnertest.New(runnertest.On(map[string]runnertest.Step{c.failing: c.step, "mid": runnertest.Fail(runner.Internal, "mid was tried")}, runnertest.Answer("answer")))
			p, _ := newPool(r, c.backends...)
			p.PrimaryFirst = true
			_, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
			if got := targets(r); !reflect.DeepEqual(got, c.want) {
				t.Errorf("targets = %v, want %v", got, c.want)
			}
			if (c.wantErr == nil && err != nil) || (c.wantErr != nil && !errors.Is(err, c.wantErr)) {
				t.Errorf("err = %v, want %v", err, c.wantErr)
			}
		})
	}
}

// The turn cap is a runaway: nothing else is tried.
func TestCall_TheTurnCapStopsTheChain(t *testing.T) {
	r := runnertest.New(runnertest.Fail(runner.TurnCap, "too many turns"))
	p, _ := newPool(r, Backend{Name: "a"}, Backend{Name: "b"})
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if !errors.Is(err, ErrTurnCapStops) || !errors.Is(err, runner.TurnCap) || len(r.Sessions()) != 1 || res.LocalClass != runner.TurnCap || res.UsedCloud {
		t.Fatalf("res = %+v, err = %v, sessions = %d", res, err, len(r.Sessions()))
	}
}

// A context-exhausted backend sends the rest biggest window first: "medium" is never tried.
func TestCall_ContextExceededTriesTheBiggestRemainingWindowNext(t *testing.T) {
	r := runnertest.New(failsOn(map[string]runnertest.Step{
		"small":  runnertest.Fail(runner.ContextExceeded, "no room"),
		"medium": runnertest.Fail(runner.Internal, "medium was tried"),
		"cloud":  runnertest.Fail(runner.Internal, "the cloud leg ran"),
	}, "big answer"))
	backends := []Backend{{Name: "small", MaxContext: 43690}, {Name: "medium", MaxContext: 65536}, {Name: "big", MaxContext: 131072}}
	p, _ := newPool(r, backends...)
	p.PrimaryFirst = true
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if err != nil || res.LocalBackendUsed != "big" || res.LocalAttempts != 2 || res.UsedCloud {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if !reflect.DeepEqual(p.Backends, backends) {
		t.Errorf("the reorder leaked into the pool's own backends: %v", p.Backends)
	}
}

// A context exhausted on every local backend is a capacity gap the cloud leg covers.
func TestCall_ContextExceededEverywhereFallsBackToTheCloud(t *testing.T) {
	r := runnertest.New(cloudAnswers(runnertest.Fail(runner.ContextExceeded, "no room")))
	p, _ := newPool(r, Backend{Name: "a", MaxContext: 131072}, Backend{Name: "b", MaxContext: 65536})
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if err != nil || !res.UsedCloud || res.LocalAttempts != 2 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

// A clean exit whose answer reports a failure is that failure: an answer check's ContextExceeded
// escalates to the bigger backend like the same failure from the session would.
func TestCall_AnAnswerCheckFailureEscalatesLikeTheSameFailure(t *testing.T) {
	r := runnertest.New(failsOn(map[string]runnertest.Step{
		"small": runnertest.Answer("cannot compress further"),
		"cloud": runnertest.Fail(runner.Internal, "the cloud leg ran"),
	}, "big answer"))
	r.AnswerCheck = func(resp string) error {
		if resp == "cannot compress further" {
			return runner.Wrap(runner.ContextExceeded, errors.New("the answer reports: "+resp))
		}
		return nil
	}
	p, _ := newPool(r, Backend{Name: "small", MaxContext: 43690}, Backend{Name: "big", MaxContext: 131072})
	p.PrimaryFirst = true
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if err != nil || res.LocalBackendUsed != "big" || res.LocalAttempts != 2 || res.Response != "big answer" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if res.Attempts[0].Class != runner.ContextExceeded || !res.Attempts[0].Failed {
		t.Errorf("attempts = %+v", res.Attempts)
	}
}

// A clean exit that reports its own failure moves to the next backend, and does not count as an
// answer.
func TestCall_AnAnswerCheckFailureMovesToTheNextBackend(t *testing.T) {
	r := runnertest.New(failsOn(map[string]runnertest.Step{"first": runnertest.Answer("the call failed after 3 retries")}, "second answer"))
	r.AnswerCheck = func(resp string) error {
		if strings.HasPrefix(resp, "the call failed") {
			return runner.Wrap(runner.BackendFault, errors.New(resp))
		}
		return nil
	}
	p, _ := newPool(r, Backend{Name: "first"}, Backend{Name: "second"})
	p.PrimaryFirst = true
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if err != nil || res.LocalBackendUsed != "second" || res.LocalAttempts != 2 || res.Response != "second answer" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

// The cloud leg's answer is the job's: it is never answer-checked.
func TestCall_TheCloudAnswerIsNeverChecked(t *testing.T) {
	r := runnertest.New(runnertest.Answer("compression gave up"))
	r.AnswerCheck = func(resp string) error { return runner.Wrap(runner.ContextExceeded, errors.New(resp)) }
	p, _ := newPool(r, Backend{Name: "a"})
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if err != nil || !res.UsedCloud || res.Response != "compression gave up" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

// An intermittent tool-call parser rejection is asked again on the same backend.
func TestCall_AnIntermittentToolCallParseIsRetriedOnTheSameBackend(t *testing.T) {
	r := runnertest.New(runnertest.Fail(runner.ToolCallParse, "parser said no"), runnertest.Answer("local answer"))
	p, _ := newPool(r, Backend{Name: "a"}, Backend{Name: "b"})
	p.PrimaryFirst = true
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if err != nil || res.UsedCloud || res.Response != "local answer" || res.LocalBackendUsed != "a" || res.LocalAttempts != 2 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if got := r.Sessions(); got[0].UsagePath != "/u/run-1.json" || got[1].UsagePath != "/u/run-1.leg2.json" {
		t.Errorf("the retry shares its leg's usage path: %q, %q", got[0].UsagePath, got[1].UsagePath)
	}
}

// A deterministic one exhausts the same-backend retries, then reaches the cloud.
func TestCall_ADeterministicToolCallParseExhaustsItsRetriesThenReachesTheCloud(t *testing.T) {
	r := runnertest.New(cloudAnswers(runnertest.Fail(runner.ToolCallParse, "parser said no")))
	p, _ := newPool(r, Backend{Name: "a"})
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if err != nil || !res.UsedCloud || res.Response != "cloud answer" || res.LocalAttempts != 1+sameBackendRetries {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

// A total failure keeps the trail, each leg classified on its own before the legs' errors are
// joined: the joined error's ClassOf is the local leg's, so the cloud leg's class is read from the
// result.
func TestCall_ATotalFailureKeepsTheTrailAndEachLegsClass(t *testing.T) {
	r := runnertest.New(runnertest.On(map[string]runnertest.Step{"cloud": runnertest.Fail(runner.TimeoutCeiling, "cloud ceiling")},
		runnertest.Fail(runner.BackendFault, "connection refused")))
	p, _ := newPool(r, Backend{Name: "a"})
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if !errors.Is(err, ErrCloudFailed) || res == nil || !res.UsedCloud || res.LocalAttempts != 1 || res.LocalFailedReason != "connection refused" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if res.LocalClass != runner.BackendFault || res.CloudClass != runner.TimeoutCeiling {
		t.Errorf("classes = local %s, cloud %s", res.LocalClass, res.CloudClass)
	}
	if !errors.Is(err, runner.BackendFault) || !errors.Is(err, runner.TimeoutCeiling) {
		t.Errorf("the joined error hides a leg's class: %v", err)
	}
	if runner.ClassOf(err) != runner.BackendFault {
		t.Errorf("ClassOf(joined) = %s: the documented pitfall moved", runner.ClassOf(err))
	}
	want := []Attempt{{Backend: "a", Failed: true, Class: runner.BackendFault}, {Cloud: true, Failed: true, Class: runner.TimeoutCeiling}}
	if !reflect.DeepEqual(res.Attempts, want) {
		t.Errorf("attempts = %+v", res.Attempts)
	}
}

// A local-only profile never reaches the cloud, and still answers locally.
func TestCall_LocalOnlyNeverStartsTheCloudLeg(t *testing.T) {
	t.Run("fails", func(t *testing.T) {
		r := runnertest.New(cloudAnswers(runnertest.Fail(runner.BackendFault, "local unreachable")))
		p, _ := newPool(r, Backend{Name: "a"})
		res, err := p.Call(context.Background(), session("run-1"), true, noAffinity, "")
		if !errors.Is(err, ErrLocalOnly) || !errors.Is(err, runner.BackendFault) || res.UsedCloud || res.LocalAttempts != 1 || res.LocalFailedReason == "" || len(r.Sessions()) != 1 {
			t.Fatalf("res = %+v, err = %v", res, err)
		}
	})
	t.Run("answers", func(t *testing.T) {
		r := runnertest.New(runnertest.Answer("local answer"))
		p, _ := newPool(r, Backend{Name: "a"})
		res, err := p.Call(context.Background(), session("run-1"), true, noAffinity, "")
		if err != nil || res.Response != "local answer" || res.UsedCloud {
			t.Fatalf("res = %+v, err = %v", res, err)
		}
	})
}

// No cloud home: there is no cloud leg, and the failure says so.
func TestCall_WithoutACloudHomeThereIsNoCloudLeg(t *testing.T) {
	r := runnertest.New(runnertest.Fail(runner.BackendFault, "local unreachable"))
	p, _ := newPool(r, Backend{Name: "a"})
	p.CloudHome = ""
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if !errors.Is(err, ErrNoCloudBackend) || res.UsedCloud || len(r.Sessions()) != 1 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

// An affinity no backend satisfies is a capacity gap: a named error for a local-only job, the cloud
// leg for any other.
func TestCall_AnAffinityNoBackendSatisfies(t *testing.T) {
	r := runnertest.New(cloudAnswers(runnertest.Fail(runner.Internal, "a local backend was tried")))
	p, _ := newPool(r, Backend{Name: "a", Tags: []string{"general"}, MaxContext: 131072})
	_, err := p.Call(context.Background(), session("run-1"), true, Affinity{RequireTags: []string{"special"}}, "")
	if !errors.Is(err, ErrNoLocalCapacity) || !strings.Contains(err.Error(), "excluded every configured local backend") || len(r.Sessions()) != 0 {
		t.Fatalf("local-only: err = %v, sessions = %v", err, targets(r))
	}
	res, err := p.Call(context.Background(), session("run-2"), false, Affinity{MinContext: 260000}, "")
	if err != nil || !res.UsedCloud || res.Response != "cloud answer" || !strings.Contains(res.LocalFailedReason, "excluded every configured local backend") || res.LocalAttempts != 0 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

// Only eligible backends are ever tried.
func TestCall_AffinityRoutesOnlyToEligibleBackends(t *testing.T) {
	r := runnertest.New(failsOn(map[string]runnertest.Step{"a": runnertest.Fail(runner.Internal, "a was tried")}, "answer from b"))
	p, _ := newPool(r, Backend{Name: "a", Tags: []string{"general"}}, Backend{Name: "b", Tags: []string{"special"}})
	for i := 0; i < 10; i++ {
		res, err := p.Call(context.Background(), session("run"), true, Affinity{RequireTags: []string{"special"}}, "")
		if err != nil || res.LocalBackendUsed != "b" {
			t.Fatalf("call %d: res = %+v, err = %v", i, res, err)
		}
	}
}

// Equal weights share real calls.
func TestCall_EqualWeightsShareRealCalls(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "a", Weight: 1}, Backend{Name: "b", Weight: 1})
	used := map[string]int{}
	for i := 0; i < 10; i++ {
		res, err := p.Call(context.Background(), session("run"), false, noAffinity, "")
		if err != nil {
			t.Fatal(err)
		}
		used[res.LocalBackendUsed]++
	}
	if used["a"] != 5 || used["b"] != 5 {
		t.Errorf("used = %v, want 5 and 5", used)
	}
}

// The reserved backend goes first, its slot counted once (at reservation), and the round-robin does
// not move for it.
func TestCall_TheReservedBackendGoesFirstAndIsNotCountedTwice(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	r := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		started <- struct{}{}
		return runnertest.Block(release, "ok", nil)(ctx, s)
	})
	p, _ := newPool(r, Backend{Name: "a", Weight: 1}, Backend{Name: "b", Weight: 1})
	ctx := context.Background()
	name, ok := p.Reserve(ctx, noAffinity, "run-1", "")
	if !ok || name != "a" {
		t.Fatalf("reserve = %q, %v", name, ok)
	}
	done := make(chan *Result)
	go func() {
		res, _ := p.Call(ctx, session("run-1"), false, noAffinity, name)
		done <- res
	}()
	<-started
	if n := p.InFlight("a"); n != 1 {
		t.Errorf("in flight on a = %d while its reserved attempt runs, want 1", n)
	}
	close(release)
	if res := <-done; res.LocalBackendUsed != "a" {
		t.Fatalf("res = %+v", res)
	}
	p.Release(name, "run-1")
	if n := p.InFlight("a"); n != 0 {
		t.Errorf("in flight on a = %d after release, want 0", n)
	}
	// One pick only for that dispatch (at Reserve): the next fresh pick goes to b.
	if got := p.selectOrder(ctx, p.Backends); got[0].Name != "b" {
		t.Errorf("the next pick = %s, want b (the round-robin advanced twice)", got[0].Name)
	}
}

// The interlock is held for the whole local attempt: a holder elsewhere keeps the attempt from
// starting, and while the session runs nobody else can take the lock.
func TestCall_HoldsTheInterlockForTheWholeLocalAttempt(t *testing.T) {
	path := lockFile(t)
	other := inference.NewInterlock(path, 10*time.Millisecond)
	held, err := other.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var duringSession error
	r := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		wctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		h, err := other.Acquire(wctx)
		if err == nil {
			_ = h.Release()
		}
		duringSession = err
		return &runner.Result{Response: "local answer"}, nil
	})
	p, _ := newPool(r, Backend{Name: "a", NeedsInterlock: true})
	p.Interlock = inference.NewInterlock(path, 10*time.Millisecond)
	done := make(chan struct{})
	go func() {
		_, _ = p.Call(context.Background(), session("run-1"), false, noAffinity, "")
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("the attempt ran while another holder had the lock")
	case <-time.After(200 * time.Millisecond):
	}
	if n := len(r.Sessions()); n != 0 {
		t.Fatalf("%d sessions started under another holder's lock", n)
	}
	_ = held.Release()
	<-done
	if !errors.Is(duringSession, inference.ErrWaitEnded) {
		t.Errorf("the lock was free during the session: %v", duringSession)
	}
}

// A wait for the interlock past the pool's bound is the backend's fault (busy): the chain moves on,
// here to the cloud, in bounded time.
func TestCall_AnInterlockWaitPastItsBoundIsABackendFault(t *testing.T) {
	path := lockFile(t)
	held, err := inference.NewInterlock(path, 10*time.Millisecond).Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	r := runnertest.New(cloudAnswers(runnertest.Answer("local answer")))
	p, _ := newPool(r, Backend{Name: "a", NeedsInterlock: true})
	p.Interlock = inference.NewInterlock(path, 10*time.Millisecond)
	p.InterlockWait = 150 * time.Millisecond
	start := time.Now()
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if err != nil || !res.UsedCloud || res.Response != "cloud answer" || res.LocalClass != runner.BackendFault {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if !strings.Contains(res.LocalFailedReason, "interlock") || time.Since(start) > 5*time.Second {
		t.Errorf("reason %q after %v", res.LocalFailedReason, time.Since(start))
	}
}

// The same wait ended by the job (a cancel or its deadline) is the job's, not the backend's: no
// cloud leg, and the chain reports the job deadline.
func TestCall_AnInterlockWaitEndedByTheJobIsNotABackendFault(t *testing.T) {
	path := lockFile(t)
	held, err := inference.NewInterlock(path, 10*time.Millisecond).Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	r := runnertest.New(cloudAnswers(runnertest.Answer("local answer")))
	p, _ := newPool(r, Backend{Name: "a", NeedsInterlock: true})
	p.Interlock = inference.NewInterlock(path, 10*time.Millisecond)
	p.InterlockWait = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	res, err := p.Call(ctx, session("run-1"), false, noAffinity, "")
	if !errors.Is(err, ErrJobDeadline) || res.UsedCloud || len(r.Sessions()) != 0 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if res.Attempts[0].Class != runner.KilledByController {
		t.Errorf("the wait's class = %s, want killed-by-controller", res.Attempts[0].Class)
	}
}

// A lock file the interlock refuses is the site's configuration, not the backend: unclassified.
func TestCall_ARefusedLockFileIsNotABackendFault(t *testing.T) {
	r := runnertest.New(cloudAnswers(runnertest.Answer("local answer")))
	p, _ := newPool(r, Backend{Name: "a", NeedsInterlock: true})
	p.Interlock = inference.NewInterlock("relative/lock", 10*time.Millisecond)
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if !errors.Is(err, ErrNotAttributable) || res.LocalClass != runner.Internal {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

// The job's limit bounds the whole chain, not each attempt: once spent, no further leg starts, the
// cloud leg included.
func TestCall_TheJobLimitBoundsTheWholeChain(t *testing.T) {
	never := make(chan struct{})
	r := runnertest.New(runnertest.Block(never, "", nil))
	p, _ := newPool(r, Backend{Name: "a"}, Backend{Name: "b"})
	p.JobLimit = 150 * time.Millisecond
	start := time.Now()
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if !errors.Is(err, ErrJobDeadline) || res == nil || res.UsedCloud {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if got := targets(r); len(got) != 1 {
		t.Errorf("legs started after the job limit: %v", got)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("the chain took %v", time.Since(start))
	}
	if p.JobTimeout() != p.JobLimit {
		t.Error("JobTimeout is not the job limit")
	}
}

// Every running attempt counts in flight, and none leaks.
func TestCall_CountsEveryRunningAttemptInFlight(t *testing.T) {
	release := make(chan struct{})
	var started sync.WaitGroup
	const n = 5
	started.Add(n)
	r := runnertest.New(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		started.Done()
		return runnertest.Block(release, "ok", nil)(ctx, s)
	})
	p, _ := newPool(r, Backend{Name: "slow"})
	var done sync.WaitGroup
	for i := 0; i < n; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			_, _ = p.Call(context.Background(), session("run"), true, noAffinity, "")
		}()
	}
	started.Wait()
	if got := p.InFlight("slow"); got != n {
		t.Errorf("in flight = %d with %d sessions running", got, n)
	}
	close(release)
	done.Wait()
	if got := p.InFlight("slow"); got != 0 {
		t.Errorf("in flight = %d after every call returned", got)
	}
}

// A cancelled session ends its attempt (the seam's contract), and the pool's count with it.
func TestCall_ACancelledJobReleasesItsAttempt(t *testing.T) {
	killed := make(chan runner.Session, 1)
	r := runnertest.New(runnertest.Block(make(chan struct{}), "", func(s runner.Session) { killed <- s }))
	p, _ := newPool(r, Backend{Name: "a"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() {
		_, err := p.Call(ctx, session("run-1"), false, noAffinity, "")
		done <- err
	}()
	for len(r.Sessions()) == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, ErrJobDeadline) {
		t.Errorf("err = %v", err)
	}
	if s := <-killed; s.Target.Backend != "a" {
		t.Errorf("killed %+v", s.Target)
	}
	if n := p.InFlight("a"); n != 0 {
		t.Errorf("in flight = %d after the cancel", n)
	}
}

func TestCall_WithoutARunnerIsAnErrorNotAPanic(t *testing.T) {
	res, err := (&Policy{Backends: []Backend{{Name: "a"}}}).Call(context.Background(), session("run-1"), false, noAffinity, "")
	if err == nil || res == nil {
		t.Fatalf("res = %v, err = %v", res, err)
	}
}

// An order emptied by drains and leases ran nothing: the chain names that, never an empty cause.
func TestCall_NothingAttemptableIsNamed(t *testing.T) {
	r := runnertest.New(cloudAnswers(runnertest.Answer("local answer")))
	p, _ := newPool(r, Backend{Name: "a"})
	if _, err := p.SetDrained("a", true); err != nil {
		t.Fatal(err)
	}
	res, err := p.Call(context.Background(), session("run-1"), false, noAffinity, "")
	if !errors.Is(err, ErrNoAttemptableBackend) || res.UsedCloud || res.LocalAttempts != 0 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

func TestLegUsagePath(t *testing.T) {
	for _, c := range []struct {
		base string
		n    int
		want string
	}{{"/u/r.json", 1, "/u/r.json"}, {"/u/r.json", 2, "/u/r.leg2.json"}, {"/u/r", 3, "/u/r.leg3.json"}, {"", 2, ""}} {
		if got := LegUsagePath(c.base, c.n); got != c.want {
			t.Errorf("LegUsagePath(%q, %d) = %q, want %q", c.base, c.n, got, c.want)
		}
	}
}

func TestRunLabel(t *testing.T) {
	if runLabel("") != "-" || runLabel("abc") != "abc" {
		t.Error("runLabel")
	}
}
