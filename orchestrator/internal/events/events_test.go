// SPDX-License-Identifier: Apache-2.0

package events

import (
	"encoding/json"
	"errors"
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
		{"t.x", "svc:a", "s\x7f", "k\x7fz", "evt-3f03de4198cce1e61939ac19eb7ace4f"},
	} {
		if got := DeriveID(c.typ, c.src, c.subj, c.key); got != c.want {
			t.Errorf("DeriveID(%q,%q,%q,%q) = %s, want %s", c.typ, c.src, c.subj, c.key, got, c.want)
		}
	}
}

func TestAsciiJSON(t *testing.T) {
	got := string(asciiJSON([]string{"caf\u00e9", "\U0001F600", "<&>", "\u2028", "a\"b\\", "\x7f"}))
	want := `["caf\u00e9","\ud83d\ude00","<&>","\u2028","a\"b\\","\u007f"]`
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

// A typed nil encodes as null, which the envelope refuses: New gives it an empty object too.
func TestNew_TypedNilDataBecomesAnObject(t *testing.T) {
	type payload struct{ X int }
	for name, d := range map[string]any{
		"nil":         nil,
		"nil map":     map[string]any(nil),
		"nil pointer": (*payload)(nil),
		"nil slice":   []any(nil),
	} {
		b, _ := json.Marshal(New("homelabnext.agent.job.started", DefaultSource, "r", "k", time.Unix(0, 0), d))
		if !strings.Contains(string(b), `"data":{}`) {
			t.Errorf("%s: %s", name, b)
		}
	}
	b, _ := json.Marshal(New("t.x", DefaultSource, "r", "k", time.Unix(0, 0), &payload{X: 1}))
	if !strings.Contains(string(b), `"data":{"X":1}`) {
		t.Errorf("a non-nil pointer was replaced: %s", b)
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

func TestNormalizeConfig_RefusesCredentialsOverPlainHTTP(t *testing.T) {
	for _, c := range []Config{
		{URL: "http://events.example.internal/ingest", BearerToken: "x"},
		{URL: "http://user:secret@events.example.internal/ingest"},
		{URL: "http://user@events.example.internal/ingest"},
	} {
		_, err := normalizeConfig(c)
		if err == nil {
			t.Errorf("%+v: accepted a credential over plain http to a remote host", c)
		} else if strings.Contains(err.Error(), "secret") {
			t.Errorf("the error shows the password: %v", err)
		}
	}
	for _, u := range []string{
		"http://127.0.0.1:1/ingest", // no-raw-endpoint: allow a loopback URL that is validated and never dialled
		"https://user:pw@events.example.internal/ingest",
	} {
		if _, err := normalizeConfig(Config{URL: u, BearerToken: "x"}); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}

func TestNormalizeConfig_ErrorsNeverEchoQueryOrUserinfo(t *testing.T) {
	for _, u := range []string{
		"ftp://user:pw@x.example.internal/a?part=zzqq#frag",
		"http://u:pw@events.example.internal/a?part=zzqq",
		"/relative?part=zzqq",
		"http://[::1%zz/x?part=zzqq",
	} {
		_, err := normalizeConfig(Config{URL: u, BearerToken: "t"})
		if err == nil {
			t.Fatalf("%s: accepted", u)
		}
		for _, leak := range []string{"zzqq", "pw@", "frag"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: error %q shows %q", u, err, leak)
			}
		}
	}
	if _, err := normalizeConfig(Config{URL: ""}); err == nil {
		t.Error("accepted an empty URL")
	}
}

func TestNormalizeConfig_Backoff(t *testing.T) {
	ok := func(base, max time.Duration) error {
		_, err := normalizeConfig(Config{URL: "https://events.example.internal/i", BaseBackoff: base, MaxBackoff: max})
		return err
	}
	for _, c := range [][2]time.Duration{{0, 0}, {time.Second, time.Second}, {time.Millisecond, time.Hour}} {
		if err := ok(c[0], c[1]); err != nil {
			t.Errorf("base %v max %v: %v", c[0], c[1], err)
		}
	}
	for _, c := range [][2]time.Duration{{-1, 0}, {0, -1}, {2 * time.Minute, 0}, {time.Second, time.Hour + 1}, {time.Minute, time.Second}} {
		if err := ok(c[0], c[1]); err == nil {
			t.Errorf("base %v max %v: accepted", c[0], c[1])
		}
	}
	if _, err := normalizeConfig(Config{URL: "https://events.example.internal/i", Timeout: -1}); err == nil {
		t.Error("accepted a negative timeout")
	}
}

// A caller's client is copied, never trusted to refuse redirects or to time out.
func TestNormalizeConfig_CopiesTheCallersClient(t *testing.T) {
	followed := false
	mine := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { followed = true; return nil }}
	cfg, err := normalizeConfig(Config{URL: "https://events.example.internal/i", HTTP: mine, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP == mine || mine.Timeout != 0 {
		t.Fatal("the caller's client was used or changed in place")
	}
	if cfg.HTTP.Timeout != 3*time.Second {
		t.Errorf("copy timeout = %v, want the configured 3s", cfg.HTTP.Timeout)
	}
	if err := cfg.HTTP.CheckRedirect(nil, nil); err != http.ErrUseLastResponse || followed {
		t.Error("the copy would follow a redirect")
	}
	set := &http.Client{Timeout: time.Second}
	if cfg, _ := normalizeConfig(Config{URL: "https://events.example.internal/i", HTTP: set}); cfg.HTTP.Timeout != time.Second {
		t.Errorf("a client's own timeout was replaced: %v", cfg.HTTP.Timeout)
	}
}

// A redirect is never followed: the sender reports it as a configuration fault.
func TestPost_NeverFollowsARedirect(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	cfg, err := normalizeConfig(Config{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if res, _ := post(cfg, "evt-x", []byte(`{}`)); res != misconfigured || hits.Load() != 1 {
		t.Fatalf("post = %d after %d requests, want misconfigured after one", res, hits.Load())
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

type failingTransport struct{ err error }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

// An unreachable forwarder's detail, which the sender logs, names the URL redacted: never its
// query, fragment or password, whatever the transport's error quotes.
func TestPost_UnreachableDetailRedactsTheURL(t *testing.T) {
	raw := "https://svc:p4ssw0rd@events.example.internal/ingest?sig=s3cret&x=1#frag-s3cret"
	for name, terr := range map[string]error{
		"plain":       errors.New("dial tcp: connection refused"),
		"quoting url": errors.New("proxy refused " + raw),
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := normalizeConfig(Config{URL: raw, HTTP: &http.Client{Transport: failingTransport{terr}}})
			if err != nil {
				t.Fatal(err)
			}
			res, detail := post(cfg, "evt-x", []byte(`{}`))
			if res != transient {
				t.Fatalf("outcome %d, want transient", res)
			}
			for _, secret := range []string{"s3cret", "p4ssw0rd", "sig=", "frag"} {
				if strings.Contains(detail, secret) {
					t.Errorf("detail %q holds %q", detail, secret)
				}
			}
			if !strings.Contains(detail, "forwarder unreachable") || !strings.Contains(detail, "events.example.internal/ingest") {
				t.Errorf("detail %q does not name the redacted URL", detail)
			}
		})
	}
}

// A short query is redacted where it stands in the URL and nowhere else: the rest of the
// message keeps its text.
func TestScrubURL_ShortQueryDoesNotGarbleTheMessage(t *testing.T) {
	raw := "https://events.example.internal/i?a=1"
	got := scrubURL(errors.New("proxy said a=1 is not allowed for https://events.example.internal/i?a=1"), raw)
	if want := "proxy said a=1 is not allowed for https://events.example.internal/i"; got != want {
		t.Errorf("scrubURL = %q, want %q", got, want)
	}
}
