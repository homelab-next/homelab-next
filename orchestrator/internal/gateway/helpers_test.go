// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// keys: every client key is at least 32 bytes (R8).
const (
	adminKey     = "admin-key-0123456789abcdef0123456789"
	telemetryKey = "telemetry-key-0123456789abcdef012345"
	agentKey     = "agent-key-0123456789abcdef0123456789"
	localKey     = "local-key-0123456789abcdef0123456789"
	upstreamKey  = "sk-upstream-provider-key"
)

var testEnv = map[string]string{
	"HNX_SECRET_ADMIN":     adminKey,
	"HNX_SECRET_TELEMETRY": telemetryKey,
	"HNX_SECRET_AGENT":     agentKey,
	"HNX_SECRET_LOCAL":     localKey,
	"HNX_SECRET_PROVIDER":  upstreamKey,
}

func envLookup(env map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := env[k]; return v, ok }
}

// fakeClock is an injected clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

func (c *fakeClock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// upstream is a fake backend that records what it was sent.
type upstream struct {
	srv     *httptest.Server
	mu      sync.Mutex
	reqs    []seen
	handler func(w http.ResponseWriter, r *http.Request, body map[string]any)
}

type seen struct {
	path   string
	header http.Header
	body   map[string]any
	raw    []byte
}

func newUpstream(t *testing.T, h func(w http.ResponseWriter, r *http.Request, body map[string]any)) *upstream {
	u := &upstream{handler: h}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		u.mu.Lock()
		u.reqs = append(u.reqs, seen{r.URL.Path, r.Header.Clone(), body, raw})
		h := u.handler
		u.mu.Unlock()
		h(w, r, body)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) calls() []seen {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]seen(nil), u.reqs...)
}

func (u *upstream) set(h func(w http.ResponseWriter, r *http.Request, body map[string]any)) {
	u.mu.Lock()
	u.handler = h
	u.mu.Unlock()
}

// openAIBackend answers like an OpenAI-compatible server: the model it names is the backend id.
func openAIBackend(reply string) func(http.ResponseWriter, *http.Request, map[string]any) {
	return func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		model, _ := body["model"].(string)
		if r.URL.Path == "/v1/embeddings" {
			writeTestJSON(w, 200, map[string]any{"object": "list", "model": model,
				"data":  []any{map[string]any{"object": "embedding", "index": 0, "embedding": []float64{0.1, 0.2}}},
				"usage": map[string]any{"prompt_tokens": 2, "total_tokens": 2}})
			return
		}
		if body["stream"] == true {
			w.Header().Set("Content-Type", "text/event-stream")
			for _, piece := range strings.Fields(reply) {
				fmt.Fprintf(w, "data: %s\n\n", mustJSON(map[string]any{"model": model, "object": "chat.completion.chunk",
					"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": piece + " "}}}}))
			}
			fmt.Fprintf(w, "data: %s\n\n", mustJSON(map[string]any{"model": model,
				"choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}}}))
			if opts, _ := body["stream_options"].(map[string]any); opts["include_usage"] == true {
				fmt.Fprintf(w, "data: %s\n\n", mustJSON(map[string]any{"model": model, "choices": []any{},
					"usage": map[string]any{"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12}}))
			}
			fmt.Fprint(w, "data: [DONE]\n\n")
			return
		}
		writeTestJSON(w, 200, map[string]any{"id": "chatcmpl-1", "object": "chat.completion", "model": "provider/" + model,
			"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": reply}, "finish_reason": "stop"}},
			"usage":   map[string]any{"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12}})
	}
}

func status(code int) func(http.ResponseWriter, *http.Request, map[string]any) {
	return func(w http.ResponseWriter, _ *http.Request, body map[string]any) {
		writeTestJSON(w, code, map[string]any{"error": map[string]any{
			"message": fmt.Sprintf("backend %v says no: secret-internal-detail", body["model"]), "type": "x"}})
	}
}

func writeTestJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// fixture is a gateway in front of fake upstreams.
type fixture struct {
	t        *testing.T
	up1, up2 *upstream // chat-a's deployments, in order
	up3      *upstream // chat-b, embed
	anth     *upstream // cloud (anthropic)
	clock    *fakeClock
	usage    string
	gw       *httptest.Server
	cfg      map[string]any

	inflight atomic.Int64 // gateway handlers running: waitIdle waits for them
}

// track counts the gateway's running handlers, so a test can wait for one that has already sent
// its reply but not yet recorded it.
func (f *fixture) track(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.inflight.Add(1)
		defer f.inflight.Add(-1)
		h.ServeHTTP(w, r)
	})
}

// waitIdle waits until no gateway handler runs.
func (f *fixture) waitIdle() {
	f.t.Helper()
	for deadline := time.Now().Add(10 * time.Second); f.inflight.Load() != 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			f.t.Fatal("a gateway handler is still running")
		}
	}
}

func dep(id, protocol, locality, url, model string, keyEnv any) map[string]any {
	return map[string]any{"id": id, "backend": "svc-" + id, "locality": locality, "protocol": protocol,
		"base_url": url, "model": model, "api_key_env": keyEnv}
}

func role(kind, ceiling string, leaves bool, deps []any, fallbacks []any, limits any) map[string]any {
	return map[string]any{"kind": kind, "max_context_tokens": 8192, "tlp_ceiling": ceiling, "leaves_lab": leaves,
		"deployments": deps, "fallbacks": fallbacks, "limits": limits, "cost_per_1k_tokens": nil}
}

func baseConfig(up1, up2, up3, anth string) map[string]any {
	return map[string]any{
		"version": "1.0", "name": "test-lab", "admin_key_env": "HNX_SECRET_ADMIN",
		"roles": map[string]any{
			"chat-a": role("chat", "red", false, []any{
				dep("chat-a-1", "openai", "local", up1, "backend-a1", nil),
				dep("chat-a-2", "openai", "local", up2, "backend-a2", nil)}, []any{"chat-b"}, nil),
			"chat-b": role("chat", "red", false, []any{dep("chat-b-1", "openai", "local", up3, "backend-b1", nil)}, []any{}, nil),
			"embed":  role("embedding", "red", false, []any{dep("embed-1", "openai", "local", up3, "backend-e1", nil)}, []any{}, nil),
			"cloud": role("chat", "green", true, []any{
				dep("cloud-1", "anthropic", "cloud", anth, "claude-backend", "HNX_SECRET_PROVIDER")}, []any{}, nil),
		},
		"keys": []any{
			map[string]any{"alias": "agent-a", "key_env": "HNX_SECRET_AGENT", "owner": "profile:agent-a",
				"data_tier": "cloud-allowed", "tlp_ceiling": "green", "roles": []any{"chat-a", "chat-b", "cloud", "embed"}, "limits": nil},
			map[string]any{"alias": "local-b", "key_env": "HNX_SECRET_LOCAL", "owner": "local-b",
				"data_tier": "local-only", "tlp_ceiling": "red", "roles": []any{"chat-b"},
				"limits": map[string]any{"window_s": 60, "max_requests": 3, "max_tokens": nil}},
		},
		"telemetry_reader": map[string]any{"key_env": "HNX_SECRET_TELEMETRY"},
	}
}

func newFixture(t *testing.T, edit ...func(cfg map[string]any)) *fixture {
	t.Helper()
	return newFixtureOpts(t, nil, edit...)
}

// newFixtureOpts is newFixture with the server's options edited by opt.
func newFixtureOpts(t *testing.T, opt func(*Options), edit ...func(cfg map[string]any)) *fixture {
	t.Helper()
	f := &fixture{t: t, clock: newClock()}
	f.up1 = newUpstream(t, openAIBackend("hello from one"))
	f.up2 = newUpstream(t, openAIBackend("hello from two"))
	f.up3 = newUpstream(t, openAIBackend("hello from three"))
	f.anth = newUpstream(t, anthropicBackend("hello from claude"))
	f.cfg = baseConfig(f.up1.srv.URL, f.up2.srv.URL, f.up3.srv.URL, f.anth.srv.URL)
	for _, e := range edit {
		e(f.cfg)
	}
	cfg, err := ParseConfig(mustJSON(f.cfg))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	sec, err := LoadSecrets(cfg, envLookup(testEnv))
	if err != nil {
		t.Fatalf("secrets: %v", err)
	}
	f.usage = filepath.Join(t.TempDir(), "usage.jsonl")
	ul, err := OpenUsageLog(f.usage)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ul.Close() })
	o := Options{Config: cfg, Secrets: sec, Usage: ul, Now: f.clock.Now, UpstreamTimeout: 2 * time.Second}
	if opt != nil {
		opt(&o)
	}
	f.gw = httptest.NewServer(f.track(New(o)))
	t.Cleanup(f.gw.Close)
	return f
}

func roleOf(cfg map[string]any, name string) map[string]any {
	return cfg["roles"].(map[string]any)[name].(map[string]any)
}

type reply struct {
	status int
	header http.Header
	body   []byte
}

func (r reply) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.body, &m); err != nil {
		t.Fatalf("not JSON (%d): %q", r.status, r.body)
	}
	return m
}

func (r reply) errCode(t *testing.T) (string, string) {
	t.Helper()
	e, _ := r.json(t)["error"].(map[string]any)
	if e == nil {
		t.Fatalf("no error envelope: %s", r.body)
	}
	typ, _ := e["type"].(string)
	code, _ := e["code"].(string)
	return typ, code
}

func (f *fixture) do(method, path, key string, body any, headers ...string) reply {
	f.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd = strings.NewReader(b)
	default:
		rd = bytes.NewReader(mustJSON(b))
	}
	req, err := http.NewRequest(method, f.gw.URL+path, rd)
	if err != nil {
		f.t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Add(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return reply{resp.StatusCode, resp.Header, data}
}

func chatBody(model string, extra ...any) map[string]any {
	b := map[string]any{"model": model, "messages": []any{map[string]any{"role": "user", "content": "Say hello."}}}
	for i := 0; i+1 < len(extra); i += 2 {
		b[extra[i].(string)] = extra[i+1]
	}
	return b
}

func (f *fixture) chat(key, model string, headers ...string) reply {
	return f.do("POST", "/v1/chat/completions", key, chatBody(model), headers...)
}

func (f *fixture) records() []map[string]any {
	f.t.Helper()
	f.waitIdle()
	r := f.do("GET", fmt.Sprintf("/v1/usage?start=0&end=%d", f.clock.Now().Unix()+10), adminKey, nil)
	if r.status != 200 {
		f.t.Fatalf("usage: %d %s", r.status, r.body)
	}
	var out struct {
		Records []map[string]any `json:"records"`
	}
	_ = json.Unmarshal(r.body, &out)
	return out.Records
}

// sseData is every data payload of an SSE body.
func sseData(body []byte) []string {
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		if d, ok := strings.CutPrefix(line, "data: "); ok {
			out = append(out, d)
		}
	}
	return out
}

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }

func deltaText(m map[string]any) string {
	ch, _ := m["choices"].([]any)
	out := ""
	for _, c := range ch {
		d, _ := c.(map[string]any)["delta"].(map[string]any)
		s, _ := d["content"].(string)
		out += s
	}
	return out
}
