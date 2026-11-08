// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner/runnertest"
)

func healthServer(t *testing.T, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var code atomic.Int32
	code.Store(int32(status))
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(code.Load()))
	}))
	t.Cleanup(s.Close)
	return s, &code
}

func absent(msg string) error {
	return runner.MarkAbsent(runner.Wrap(runner.BackendFault, errors.New(msg)))
}

// The pool's backend-down verdicts are its own sentinels, read by type wherever they are wrapped.
func TestIsBackendDownIsTyped(t *testing.T) {
	if !IsBackendDown(fmt.Errorf("%w: %w", ErrLocalOnly, fmt.Errorf("%w ([a])", ErrNoHealthyBackend))) {
		t.Error("a wrapped ErrNoHealthyBackend")
	}
	if !IsBackendDown(fmt.Errorf("x: %w", ErrBackendUnreachable)) {
		t.Error("a wrapped ErrBackendUnreachable")
	}
	if IsBackendDown(errors.New(ErrNoHealthyBackend.Error())) || IsBackendDown(absent("connection refused")) {
		t.Error("text or a hint read as the pool's verdict")
	}
}

func TestBackendUp_UnknownIsUpAndProbesHaveHysteresis(t *testing.T) {
	p, _ := newPool(nil)
	if !p.BackendUp("a") {
		t.Fatal("a backend never probed is down")
	}
	refused := &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	p.recordProbe("a", refused)
	if !p.BackendUp("a") {
		t.Fatal("one failed probe marked it down")
	}
	p.recordProbe("a", refused)
	if p.BackendUp("a") {
		t.Fatal("two failed probes in a row left it up")
	}
	p.recordProbe("a", nil)
	if !p.BackendUp("a") {
		t.Fatal("a good probe left it down")
	}
}

func TestProbeOnce_ProbesEveryHealthURL(t *testing.T) {
	srv, code := healthServer(t, http.StatusOK)
	p, _ := newPool(nil, Backend{Name: "watched", HealthURL: srv.URL}, Backend{Name: "noprobe"})
	ctx := context.Background()
	p.ProbeOnce(ctx)
	if !p.BackendUp("watched") {
		t.Fatal("200 is down")
	}
	code.Store(http.StatusBadGateway) // a proxy up, its engine gone
	p.ProbeOnce(ctx)
	p.ProbeOnce(ctx)
	if p.BackendUp("watched") || !p.BackendUp("noprobe") {
		t.Fatalf("watched up=%v noprobe up=%v", p.BackendUp("watched"), p.BackendUp("noprobe"))
	}
	snap := p.HealthSnapshot()
	if len(snap) != 2 || snap[1].Backend != "watched" || snap[1].Up || snap[1].LastError == "" || snap[1].ErrorClass != "probe_failed:http_status" {
		t.Fatalf("snapshot = %+v", snap)
	}
}

// The passive path never decides on a failure's text or hint: the hint triggers one probe and the
// probe decides. The probe runs detached from the job's context.
func TestConfirmBackendDown_TheProbeDecides(t *testing.T) {
	up, _ := healthServer(t, http.StatusOK)
	down, _ := healthServer(t, http.StatusBadGateway)
	ctx := context.Background()
	p, _ := newPool(nil)
	hinted := absent("Connection refused, said the model")
	if err := p.confirmBackendDown(ctx, Backend{Name: "up", HealthURL: up.URL}, hinted); err != hinted || IsBackendDown(err) || !p.BackendUp("up") {
		t.Errorf("a backend that answers its probe: %v", err)
	}
	if err := p.confirmBackendDown(ctx, Backend{Name: "unwatched"}, hinted); IsBackendDown(err) || !p.BackendUp("unwatched") {
		t.Error("without a probe nothing can confirm (or undo) an outage")
	}
	slow := runner.Wrap(runner.TimeoutCeiling, errors.New("still working when the ceiling fired"))
	if err := p.confirmBackendDown(ctx, Backend{Name: "down", HealthURL: down.URL}, slow); IsBackendDown(err) || !p.BackendUp("down") {
		t.Error("a failure with no absent hint was probed")
	}
	err := p.confirmBackendDown(ctx, Backend{Name: "down", HealthURL: down.URL}, hinted)
	if !errors.Is(err, ErrBackendUnreachable) || p.BackendUp("down") || runner.ClassOf(err) != runner.BackendFault {
		t.Fatalf("a confirmed outage: %v (up %v, class %s)", err, p.BackendUp("down"), runner.ClassOf(err))
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	q, _ := newPool(nil)
	if err := q.confirmBackendDown(cctx, Backend{Name: "up", HealthURL: up.URL}, hinted); IsBackendDown(err) || !q.BackendUp("up") {
		t.Errorf("a cancelled job's context failed the probe: %v", err)
	}
}

// A confirmed outage in a call marks the backend down at once and reaches the next backend or the
// cloud; a BackendFault alone never marks anything down.
func TestCall_OnlyAConfirmedOutageMarksABackendDown(t *testing.T) {
	down, _ := healthServer(t, http.StatusServiceUnavailable)
	r := runnertest.New(cloudAnswers(func(context.Context, runner.Session) (*runner.Result, error) {
		return &runner.Result{}, absent("nothing answered")
	}))
	p, _ := newPool(r, Backend{Name: "a", HealthURL: down.URL})
	res, err := p.Call(context.Background(), session("run-1"), CloudFallback, noAffinity, "")
	if err != nil || !res.UsedCloud || p.BackendUp("a") {
		t.Fatalf("res = %+v, err = %v, up = %v", res, err, p.BackendUp("a"))
	}
	r2 := runnertest.New(cloudAnswers(runnertest.Fail(runner.BackendFault, "connection refused")))
	q, _ := newPool(r2, Backend{Name: "a", HealthURL: down.URL})
	if _, err := q.Call(context.Background(), session("run-1"), CloudFallback, noAffinity, ""); err != nil || !q.BackendUp("a") {
		t.Fatalf("a fault without the hint marked the backend down (err %v)", err)
	}
}

func TestReserve_SkipsDownBackends(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "big", HealthURL: "u", Weight: 8}, Backend{Name: "small", HealthURL: "u", Weight: 1})
	ctx := context.Background()
	p.setHealth("big", false, "probe_failed", nil, "test")
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("r%d", i)
		name, ok := p.Reserve(ctx, Affinity{}, id, "")
		if !ok || name != "small" {
			t.Fatalf("reserve %d = %q, %v; want small (big is down)", i, name, ok)
		}
		p.Release(name, id)
	}
	p.setHealth("small", false, "probe_failed", nil, "test")
	if _, ok := p.Reserve(ctx, Affinity{}, "r", ""); ok {
		t.Fatal("admitted with nothing healthy")
	}
	if p.AnyHealthy(Affinity{}) {
		t.Fatal("AnyHealthy with nothing healthy")
	}
	if !p.AnyHealthy(Affinity{RequireTags: []string{"none"}}) {
		t.Fatal("nothing eligible read as an outage")
	}
}

// Every eligible backend down: no session at all, and the cause is the pool's typed verdict.
func TestCall_AllDownLocalOnlyFailsFastWithoutASession(t *testing.T) {
	r := runnertest.New()
	p, _ := newPool(r, Backend{Name: "a", HealthURL: "u"})
	p.setHealth("a", false, "probe_failed", nil, "test")
	res, err := p.Call(context.Background(), session("run-1"), LocalOnly, noAffinity, "")
	if !errors.Is(err, ErrNoHealthyBackend) || !IsBackendDown(err) || res.LocalAttempts != 0 || len(r.Sessions()) != 0 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	res, err = p.Call(context.Background(), session("run-2"), CloudFallback, noAffinity, "")
	if err != nil || !res.UsedCloud {
		t.Fatalf("every backend down is the cloud leg's case: res = %+v, err = %v", res, err)
	}
}

// The snapshot's class comes from the probe's typed error; Redacted drops the text, which can quote
// a session's output.
func TestHealthSnapshot_TheErrorClassComesFromTheProbesType(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, "probe_failed:connection_refused"},
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}, "probe_failed:unreachable"},
		{&net.DNSError{Err: "no such host", Name: "engine.example.internal"}, "probe_failed:dns"},
		{context.DeadlineExceeded, "probe_failed:timeout"},
		{errHTTPStatus(503), "probe_failed:http_status"},
		{fmt.Errorf("read: %w", syscall.ECONNRESET), "probe_failed:connection_reset"},
		{errors.New("connection refused, timeout, status, eof"), "probe_failed"},
	} {
		p, _ := newPool(nil, Backend{Name: "a", HealthURL: "u"})
		p.recordProbe("a", c.err)
		p.recordProbe("a", c.err)
		if got := p.HealthSnapshot()[0].ErrorClass; got != c.want {
			t.Errorf("%v: class %q, want %q", c.err, got, c.want)
		}
	}
	p, _ := newPool(nil, Backend{Name: "a", HealthURL: "u"})
	p.setHealth("a", false, "call_failed", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, "call failed: the session said: secret")
	s := p.HealthSnapshot()[0]
	r := s.Redacted()
	if s.ErrorClass != "call_failed:connection_refused" || r.LastError != "" || r.ErrorClass != s.ErrorClass || r.Up || r.Backend != "a" {
		t.Errorf("snapshot %+v, redacted %+v", s, r)
	}
	p.setHealth("a", true, "", nil, "")
	if s := p.HealthSnapshot()[0]; !s.Up || s.ErrorClass != "" || s.LastError != "" {
		t.Errorf("up again: %+v", s)
	}
}

// The pool's only HTTP traffic is GETs, with no body, to the probe URLs it was given.
func TestTheProbesAreGETsOnly(t *testing.T) {
	type req struct {
		method, path string
		body         int64
	}
	var mu = make(chan struct{}, 1)
	var seen []req
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu <- struct{}{}
		seen = append(seen, req{r.Method, r.URL.Path, r.ContentLength})
		<-mu
		_, _ = w.Write([]byte("engine:requests_running 0\n" + `engine:cache_info{pool_tokens="1000000"} 1` + "\n"))
	}))
	defer srv.Close()
	r := runnertest.New(cloudAnswers(func(context.Context, runner.Session) (*runner.Result, error) {
		return &runner.Result{}, absent("nothing answered")
	}))
	p, _ := newPool(r, Backend{Name: "a", MaxConcurrent: 4, HealthURL: srv.URL + "/health", LoadProbeURLs: []string{srv.URL + "/metrics"}}, Backend{Name: "b", MaxConcurrent: 4})
	p.LoadMetrics, p.KV, p.TokenWeightedAdmission = testLoadMetrics, testKV, true
	ctx := context.Background()
	p.ProbeOnce(ctx)
	name, _ := p.Reserve(ctx, Affinity{}, "run-1", "agent")
	_, _ = p.Call(ctx, session("run-1"), CloudFallback, Affinity{}, name)
	_, _ = p.ReserveExclusive(ctx, Affinity{Exclusive: true, ExcludeBackends: []string{"b"}}, "run-2")
	mu <- struct{}{}
	defer func() { <-mu }()
	if len(seen) == 0 {
		t.Fatal("no probe was made")
	}
	for _, q := range seen {
		if q.method != http.MethodGet || q.body > 0 || (q.path != "/health" && q.path != "/metrics") {
			t.Errorf("request %+v: the pool sends nothing but probe GETs", q)
		}
	}
}
