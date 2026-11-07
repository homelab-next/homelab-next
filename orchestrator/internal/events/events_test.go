// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// DeriveID agrees with homelabnext.events.envelope.derive_event_id (each value below computed
// with it), so a controller event and a Python publisher agree on what "the same event" is,
// non-ASCII text, line separators and control characters included.
func TestDeriveID_MatchesThePythonDerivation(t *testing.T) {
	for _, c := range []struct{ typ, src, subj, key, want string }{
		{"homelabnext.agent.job.started", "svc:orchestrator", "0123abcd", "0123abcd:homelabnext.agent.job.started", "evt-7c6ffffc9e1247f7765210c396fd31e6"},
		{"homelabnext.task.queued", "svc:siem", "", "job-17", "evt-fc5dd6b1e9046c2df0131ba4949ca363"},
		{"t.x", "svc:a", "s", "k<&>", "evt-2342b253dc5b8f54fcc9e95b7ec0db7c"},
		{"t.x", "svc:a", "caf\u00e9", "k\u2028\U0001F600\n\x01", "evt-d201f3b562ba841cb6c9df1561a1b081"},
	} {
		if got := DeriveID(c.typ, c.src, c.subj, c.key); got != c.want {
			t.Errorf("DeriveID(%q,%q,%q,%q) = %s, want %s", c.typ, c.src, c.subj, c.key, got, c.want)
		}
	}
}

func TestAsciiJSON(t *testing.T) {
	got := string(asciiJSON([]string{"caf\u00e9", "\U0001F600", "<&>", "\u2028", "a\"b\\"}))
	want := `["caf\u00e9","\ud83d\ude00","<&>","\u2028","a\"b\\"]`
	if got != want {
		t.Fatalf("asciiJSON = %s, want %s", got, want)
	}
}

func TestValidSource(t *testing.T) {
	if !ValidSource(DefaultSource) {
		t.Errorf("DefaultSource %q is not a valid source", DefaultSource)
	}
	for _, s := range []string{"orchestrator", "svc:Bad", "svc:", "svc:a--b", "svc:-a", "cap:orchestrator", "svc:" + strings.Repeat("a", 125)} {
		if ValidSource(s) {
			t.Errorf("ValidSource(%q) = true", s)
		}
	}
}

func TestNew(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 600000000, time.FixedZone("x", 3600))
	e := New("homelabnext.agent.job.started", DefaultSource, "run-1", "run-1:started", at, map[string]any{"run_id": "run-1"})
	if e.SpecVersion != "1.0" || e.Time != "2026-01-02T02:04:05.6Z" || e.Subject != "run-1" ||
		e.ID != DeriveID(e.Type, e.Source, e.Subject, "run-1:started") {
		t.Fatalf("New = %+v", e)
	}
}

type fakeForwarder struct {
	mu       sync.Mutex
	statuses []int // served in order, then 202
	got      []map[string]any
	headers  []http.Header
}

func (f *fakeForwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	code := http.StatusAccepted
	if len(f.statuses) > 0 {
		code, f.statuses = f.statuses[0], f.statuses[1:]
	}
	if code < 300 {
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		f.got = append(f.got, m)
		f.headers = append(f.headers, r.Header.Clone())
	}
	if code >= 300 && code < 400 {
		w.Header().Set("Location", "/elsewhere")
	}
	w.WriteHeader(code)
}

func newPub(t *testing.T, url string, mod func(*Config)) *HTTPPublisher {
	t.Helper()
	cfg := Config{URL: url, BaseBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond}
	if mod != nil {
		mod(&cfg)
	}
	p, err := NewHTTPPublisher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func closePub(p *HTTPPublisher) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p.Close(ctx)
}

// The envelope goes out as application/cloudevents+json with Idempotency-Key = id; transient and
// configuration answers are retried with the same id, a permanent refusal is not.
func TestPublisher_ContractAndRetries(t *testing.T) {
	f := &fakeForwarder{statuses: []int{503, 429, 401, 202, 400}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	p := newPub(t, srv.URL, func(c *Config) { c.BearerToken = "tok" })

	e1 := New("homelabnext.agent.job.started", DefaultSource, "r1", "r1:started", time.Unix(0, 0), map[string]any{"run_id": "r1"})
	e2 := New("homelabnext.agent.job.failed", DefaultSource, "r1", "r1:failed", time.Unix(0, 0), map[string]any{"run_id": "r1"})
	p.Publish(e1) // 503, 429, 401, then 202
	p.Publish(e2) // 400: permanent
	waitFor(t, func() bool { st := p.Stats(); return st.Published+st.Rejected+st.Failed >= 2 })
	closePub(p)

	st := p.Stats()
	if st.Published != 1 || st.Rejected != 1 || st.Failed != 0 || st.Dropped != 0 {
		t.Fatalf("stats = %+v", st)
	}
	if len(f.got) != 1 || f.got[0]["id"] != e1.ID || f.got[0]["specversion"] != "1.0" || f.got[0]["type"] != e1.Type {
		t.Fatalf("forwarder got %v", f.got)
	}
	h := f.headers[0]
	if h.Get("Content-Type") != ContentType || h.Get(IdempotencyHdr) != e1.ID || h.Get("Authorization") != "Bearer tok" {
		t.Errorf("headers = %v", h)
	}
}

func TestPublisher_GivesUpAfterBudget(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.WriteHeader(500)
	}))
	defer srv.Close()
	p := newPub(t, srv.URL, func(c *Config) { c.MaxAttempts = 3 })
	p.Publish(New("homelabnext.agent.job.started", DefaultSource, "r", "k", time.Now(), nil))
	// let the worker spend its budget before Close turns retries off
	waitFor(t, func() bool { return p.Stats().Failed > 0 })
	closePub(p)
	if n.Load() != 3 || p.Stats().Failed != 1 {
		t.Errorf("attempts = %d, stats = %+v; want 3 attempts and 1 failed", n.Load(), p.Stats())
	}
}

// A full queue drops instead of blocking the job.
func TestPublisher_NeverBlocks(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(202)
	}))
	defer srv.Close()
	defer close(release)
	p := newPub(t, srv.URL, func(c *Config) { c.QueueSize = 1 })
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			p.Publish(New("homelabnext.agent.job.started", DefaultSource, "r", string(rune('a'+i)), time.Now(), nil))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a full queue")
	}
	if p.Stats().Dropped == 0 {
		t.Error("no drops counted for a full queue")
	}
}

func TestNewHTTPPublisher_RefusesTokenOverPlainHTTP(t *testing.T) {
	if _, err := NewHTTPPublisher(Config{URL: "http://events.example.internal/ingest", BearerToken: "x"}); err == nil {
		t.Error("accepted a bearer token over plain http to a remote host")
	}
	for _, u := range []string{"ftp://x", "/ingest", "http://", ""} {
		if _, err := NewHTTPPublisher(Config{URL: u}); err == nil {
			t.Errorf("accepted %q", u)
		}
	}
	p, err := NewHTTPPublisher(Config{URL: "http://127.0.0.1:1/ingest", BearerToken: "x"}) // no-raw-endpoint: allow a loopback URL that is validated and never dialled
	if err != nil {
		t.Errorf("refused loopback http: %v", err)
	} else {
		closePub(p)
	}
}

// The contract's outcomes (docs/events.md, "Forwarder contract").
func TestClassify(t *testing.T) {
	for code, want := range map[int]outcome{
		200: accepted, 201: accepted, 202: accepted, 204: accepted,
		408: transient, 425: transient, 429: transient, 500: transient, 503: transient,
		301: misconfigured, 302: misconfigured, 307: misconfigured, 401: misconfigured, 403: misconfigured, 404: misconfigured, 421: misconfigured,
		400: permanent, 409: permanent, 410: permanent, 422: permanent,
	} {
		if got := classify(code); got != want {
			t.Errorf("classify(%d) = %d, want %d", code, got, want)
		}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached within 5s")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
