// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// knownAgents are the agent keys the tests' profiles cover.
var knownAgents = map[string]bool{"watcher": true, "collector": true}

func agentKnown(k string) bool { return knownAgents[k] }

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "orch.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// testAPI is the API over a new store, unauthenticated unless cfg sets Auth.
type testAPI struct {
	t   *testing.T
	st  *store.Store
	srv *httptest.Server
}

func newAPI(t *testing.T, tweak func(*Config)) *testAPI {
	t.Helper()
	st := openStore(t)
	cfg := Config{Store: st, AgentKnown: agentKnown, Unauthenticated: true}
	if tweak != nil {
		tweak(&cfg)
	}
	if cfg.Auth != nil {
		cfg.Unauthenticated = false
	}
	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &testAPI{t: t, st: st, srv: srv}
}

// do sends a request with an optional bearer token and JSON body, and returns the status and body.
func (a *testAPI) do(method, path, token string, body any) (int, []byte) {
	a.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, a.srv.URL+path, rd)
	if err != nil {
		a.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := a.srv.Client().Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (a *testAPI) submit(token string, body map[string]any) (int, SubmitResponse, SubmitError) {
	a.t.Helper()
	code, out := a.do(http.MethodPost, "/jobs", token, body)
	var ok SubmitResponse
	var bad SubmitError
	_ = json.Unmarshal(out, &ok)
	_ = json.Unmarshal(out, &bad)
	return code, ok, bad
}

func (a *testAPI) getJob(token, id string) (int, JobResponse) {
	a.t.Helper()
	code, out := a.do(http.MethodGet, "/jobs/"+id, token, nil)
	var j JobResponse
	_ = json.Unmarshal(out, &j)
	return code, j
}

// failed stores a failed job of agent with class, owned by owner.
func (a *testAPI) failed(id, agent, class, owner string) {
	a.t.Helper()
	j := &store.Job{RunID: id, AgentKey: agent, Priority: 50, State: store.StateRunning, CreatedAt: time.Now().UTC(),
		TaskDescription: "the parent's task", SubmittedBy: owner}
	if err := a.st.CreateJob(j); err != nil {
		a.t.Fatal(err)
	}
	if err := a.st.UpdateStateClass(id, store.StateRunning, store.StateFailed, class); err != nil {
		a.t.Fatal(err)
	}
}

// tokens writes a tokens file owner-only and loads it; each caller's token is "tok-<caller>".
func tokens(t *testing.T, scopes map[string][]string) *Authenticator {
	t.Helper()
	var b strings.Builder
	b.WriteString("tokens:\n")
	for caller, sc := range scopes {
		d := sha256.Sum256([]byte("tok-" + caller))
		b.WriteString("  - caller: " + caller + "\n    sha256: " + hex.EncodeToString(d[:]) + "\n    scopes: [" + strings.Join(sc, ", ") + "]\n")
	}
	path := filepath.Join(t.TempDir(), "tokens.yaml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := LoadAuthenticator(path)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// httptestServer serves h and returns its URL, closed at cleanup.
func httptestServer(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}
