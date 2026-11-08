// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// A resubmit takes its parent's lane whatever the request said, so its replay is the same
// submit whether or not it repeats the parent's shadow flag.
func TestResubmit_ReplayOfAShadowParentsRetryIs200(t *testing.T) {
	a := newAPI(t, nil)
	if err := a.st.CreateJob(&store.Job{RunID: "p-shadow", AgentKey: "watcher", Priority: 50, State: store.StateRunning,
		Shadow: true, CreatedAt: time.Now().UTC(), TaskDescription: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := a.st.UpdateStateClass("p-shadow", store.StateRunning, store.StateFailed, store.FailureStall); err != nil {
		t.Fatal(err)
	}
	code, first, _ := a.submit("", retryBody("p-shadow", "e1", "stall"))
	if code != http.StatusCreated {
		t.Fatal(code)
	}
	if j, _ := a.st.GetJob(first.RunID); !j.Shadow {
		t.Fatal("the resubmit did not take its parent's lane")
	}
	if code, again, bad := a.submit("", retryBody("p-shadow", "e1", "stall")); code != http.StatusOK || again.RunID != first.RunID {
		t.Fatalf("the identical replay = %d %+v %+v", code, again, bad)
	}
}

// A submit body is one JSON object of the submit's keys, each spelled exactly and given once.
func TestSubmit_BodyIsDecodedStrictly(t *testing.T) {
	a := newAPI(t, nil)
	for name, body := range map[string]string{
		"duplicate key":         `{"agent_key":"watcher","input":{"x":1},"input":null}`,
		"duplicate agent":       `{"agent_key":"nobody","agent_key":"watcher"}`,
		"unknown key":           `{"agent_key":"watcher","priorty":5}`,
		"another case":          `{"Agent_Key":"watcher"}`,
		"trailing data":         `{"agent_key":"watcher"} {"agent_key":"watcher"}`,
		"trailing garbage":      `{"agent_key":"watcher"}x`,
		"an array":              `[{"agent_key":"watcher"}]`,
		"a wrong-typed value":   `{"agent_key":"watcher","priority":"high"}`,
		"a non-slug profile id": `{"agent_key":"watcher","profile_id":"a b"}`,
		"an over-long profile":  `{"agent_key":"watcher","profile_id":"` + strings.Repeat("p", maxProfileIDLen+1) + `"}`,
	} {
		if code, _ := a.do(http.MethodPost, "/jobs", "", body); code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", name, code)
		}
	}
	if jobs, _ := a.st.ListJobs(store.ListFilter{Limit: 10}); len(jobs) != 0 {
		t.Fatalf("%d jobs stored", len(jobs))
	}
	if code, _ := a.do(http.MethodPost, "/jobs", "", `{"agent_key":"watcher","profile_id":"watcher-v1"}`); code != http.StatusCreated {
		t.Fatalf("a valid profile id = %d", code)
	}
}

// One caller's unfinished jobs are bounded; another caller's are not counted against it.
func TestSubmit_UnfinishedJobsArePerCallerBounded(t *testing.T) {
	a := newAPI(t, func(c *Config) {
		c.MaxUnfinishedPerCaller = 2
		c.Auth = tokens(t, map[string][]string{"alice": {"jobs"}, "bob": {"jobs"}})
	})
	for i := 0; i < 2; i++ {
		if code, _, _ := a.submit("tok-alice", map[string]any{"agent_key": "watcher"}); code != http.StatusCreated {
			t.Fatal(code)
		}
	}
	if code, _, _ := a.submit("tok-alice", map[string]any{"agent_key": "watcher"}); code != http.StatusTooManyRequests {
		t.Fatalf("a third unfinished job = %d", code)
	}
	if code, _, _ := a.submit("tok-bob", map[string]any{"agent_key": "watcher"}); code != http.StatusCreated {
		t.Fatalf("bob was held by alice's jobs: %d", code)
	}
	jobs, _ := a.st.ListJobs(store.ListFilter{SubmittedBy: "alice", Limit: 10})
	if err := a.st.UpdateState(jobs[0].RunID, store.StateQueued, store.StateCancelled); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := a.submit("tok-alice", map[string]any{"agent_key": "watcher"}); code != http.StatusCreated {
		t.Fatalf("after one finished = %d", code)
	}
}

// What a caller controls reaches the log quoted, so a newline cannot forge a line, and a flood of
// unknown tokens is logged once per interval.
func TestLogs_QuoteWhatTheCallerControlsAndRateLimitUnknownTokens(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	a := newAPI(t, func(c *Config) {
		c.Auth = tokens(t, map[string][]string{"ops": {"admin"}})
		c.BackendDrain = func(string, bool) (any, error) { return map[string]any{}, nil }
	})
	a.do(http.MethodPost, "/admin/backends/engine-a%0Aapi:%20forged/drain", "tok-ops", nil)
	for i := 0; i < 20; i++ {
		a.do(http.MethodGet, "/jobs%0Aapi: forged", "bogus", nil)
	}
	out := buf.String()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "api: forged") {
			t.Fatalf("a forged line: %q", out)
		}
	}
	if n := strings.Count(out, "refused an unknown token"); n != 1 {
		t.Fatalf("%d unknown-token lines for 20 requests", n)
	}
}

// pprof is never served without authentication, and NewServer reports a missing authenticator
// before the address.
func TestPprofAndServerChecks(t *testing.T) {
	st := openStore(t)
	if _, err := NewHandler(Config{Store: st, AgentKnown: agentKnown, Unauthenticated: true, Pprof: true}); !errors.Is(err, ErrInsecure) {
		t.Fatalf("pprof unauthenticated = %v", err)
	}
	_, err := NewServer("0.0.0.0:8088", Config{Store: st, AgentKnown: agentKnown})
	if !errors.Is(err, ErrInsecure) || !strings.Contains(err.Error(), "authentication is on by default") {
		t.Fatalf("no authenticator off loopback = %v, want the authentication error first", err)
	}
}

// The scope is the route's the request reaches, whatever its spelling: a path that cleans to an
// admin route is judged admin.
func TestRouteScope_IsTheMatchedRoutes(t *testing.T) {
	a := newAPI(t, func(c *Config) { c.Auth = tokens(t, map[string][]string{"app": {"jobs"}}) })
	for _, p := range []string{"/jobs/../admin/queue-summary", "/jobs/x/../../admin/queue-summary", "//admin/queue-summary"} {
		req, _ := http.NewRequest(http.MethodGet, a.srv.URL+p, nil)
		req.URL.Opaque = p // sent as written, not cleaned by the client
		req.Header.Set("Authorization", "Bearer tok-app")
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("%s reached the queue summary with a jobs token", p)
		}
	}
}

// A repeated session id filter is refused.
func TestListJobs_RepeatedSessionIDIsRefused(t *testing.T) {
	a := newAPI(t, nil)
	if code, _ := a.do(http.MethodGet, "/jobs?session_id=a&session_id=b", "", nil); code != http.StatusBadRequest {
		t.Fatalf("a repeated session_id = %d", code)
	}
}

// No response body carries an error's text: the status command's, the eligibility's and the
// metrics writer's errors stay in the log.
func TestErrorTextNeverReachesAResponse(t *testing.T) {
	secret := errors.New("SECRET-ERROR-TEXT")
	a := newAPI(t, func(c *Config) {
		c.BackendStatus = func(context.Context) ([]byte, error) { return nil, secret }
		c.BackendEligibility = func(string) ([]BackendEligibilityEntry, error) { return nil, secret }
		c.Metrics = func(io.Writer) error { return secret }
		c.ReloadProfiles = func() error { return secret }
		c.BackendDrain = func(string, bool) (any, error) { return nil, secret }
	})
	for _, c := range []struct{ method, path string }{
		{"GET", "/admin/backend-status"}, {"GET", "/admin/backend-eligibility?backend=a"}, {"GET", "/metrics"},
		{"POST", "/admin/reload-profiles"}, {"POST", "/admin/backends/a/drain"},
	} {
		if _, out := a.do(c.method, c.path, "", nil); strings.Contains(string(out), "SECRET") {
			t.Errorf("%s %s answered %q", c.method, c.path, out)
		}
	}
}

// No response writer is given an error: no argument of http.Error, writeJSON or submitError
// mentions an error variable or calls Error().
func TestNoResponseIsBuiltFromAnError(t *testing.T) {
	entries, _ := os.ReadDir(".")
	fset := token.NewFileSet()
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", e.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isResponseWriter(call.Fun) {
				return true
			}
			for _, arg := range call.Args {
				ast.Inspect(arg, func(m ast.Node) bool {
					switch x := m.(type) {
					case *ast.Ident:
						if x.Name == "err" || strings.HasSuffix(x.Name, "Err") || strings.HasSuffix(x.Name, "err") {
							t.Errorf("%s: a response is built from %s", fset.Position(x.Pos()), x.Name)
						}
					case *ast.SelectorExpr:
						if x.Sel.Name == "Error" {
							t.Errorf("%s: a response is built from an Error() call", fset.Position(x.Pos()))
						}
					}
					return true
				})
			}
			return true
		})
	}
}

func isResponseWriter(fun ast.Expr) bool {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name == "writeJSON" || f.Name == "submitError"
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok && x.Name == "http" && f.Sel.Name == "Error" {
			return true
		}
	}
	return false
}
