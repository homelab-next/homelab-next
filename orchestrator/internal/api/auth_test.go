// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Authentication is on by default: a handler with no authenticator is refused unless
// Unauthenticated is set explicitly, and both at once are refused.
func TestNewHandler_AuthIsOnByDefault(t *testing.T) {
	st := openStore(t)
	if _, err := NewHandler(Config{Store: st, AgentKnown: agentKnown}); !errors.Is(err, ErrInsecure) {
		t.Fatalf("no auth, no opt-out = %v", err)
	}
	if _, err := NewHandler(Config{Store: st, AgentKnown: agentKnown, Unauthenticated: true, Auth: tokens(t, map[string][]string{"a": {"admin"}})}); !errors.Is(err, ErrInsecure) {
		t.Fatalf("both = %v", err)
	}
	if _, err := NewHandler(Config{Store: st, Unauthenticated: true}); err == nil {
		t.Fatal("no agent-key check was accepted")
	}
}

// An unauthenticated API binds a loopback IP literal only; with auth on any address is allowed.
func TestCheckBind_NonLoopbackWithoutAuthIsRefused(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8088", "[::1]:8088", "127.0.0.2:1"} {
		if err := CheckBind(addr, false); err != nil {
			t.Errorf("%s refused: %v", addr, err)
		}
	}
	for _, addr := range []string{":8088", "0.0.0.0:8088", "[::]:8088", "localhost:8088", "198.51.100.7:8088", "nonsense"} {
		if err := CheckBind(addr, false); !errors.Is(err, ErrInsecure) {
			t.Errorf("%s accepted unauthenticated: %v", addr, err)
		}
		if err := CheckBind(addr, true); err != nil && addr != "nonsense" {
			t.Errorf("%s refused with auth on: %v", addr, err)
		}
	}
	st := openStore(t)
	if _, err := NewServer("0.0.0.0:8088", Config{Store: st, AgentKnown: agentKnown, Unauthenticated: true}); !errors.Is(err, ErrInsecure) {
		t.Fatalf("NewServer off loopback unauthenticated = %v", err)
	}
	srv, err := NewServer("127.0.0.1:0", Config{Store: st, AgentKnown: agentKnown, Unauthenticated: true})
	if err != nil || srv.ReadHeaderTimeout == 0 || srv.MaxHeaderBytes == 0 {
		t.Fatalf("NewServer = %+v, %v", srv, err)
	}
}

// pprof is served only when asked for, and then behind the admin scope.
func TestPprofIsGated(t *testing.T) {
	if code, _ := newAPI(t, nil).do(http.MethodGet, "/debug/pprof/", "", nil); code != http.StatusNotFound {
		t.Fatalf("pprof off = %d", code)
	}
	a := newAPI(t, func(c *Config) {
		c.Pprof = true
		c.Auth = tokens(t, map[string][]string{"ops": {"admin"}, "app": {"jobs", "metrics"}})
	})
	if code, _ := a.do(http.MethodGet, "/debug/pprof/", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("pprof without a token = %d", code)
	}
	if code, _ := a.do(http.MethodGet, "/debug/pprof/", "tok-app", nil); code != http.StatusForbidden {
		t.Fatalf("pprof with a jobs token = %d", code)
	}
	if code, _ := a.do(http.MethodGet, "/debug/pprof/", "tok-ops", nil); code != http.StatusOK {
		t.Fatalf("pprof as admin = %d", code)
	}
}

func TestAuth_ScopesAndOpenRoutes(t *testing.T) {
	a := newAPI(t, func(c *Config) {
		c.Auth = tokens(t, map[string][]string{"ops": {"admin"}, "app": {"jobs"}, "scrape": {"metrics"}})
		c.Metrics = func(w io.Writer) error { return nil }
	})
	for _, c := range []struct {
		method, path, token string
		want                int
	}{
		{"GET", "/healthz", "", 200},
		{"GET", "/healthz", "bogus", 200},
		{"GET", "/jobs", "", 401},
		{"GET", "/jobs", "bogus", 401},
		{"GET", "/jobs", "tok-app", 200},
		{"GET", "/jobs", "tok-scrape", 403},
		{"GET", "/metrics", "tok-scrape", 200},
		{"GET", "/metrics", "tok-app", 403},
		{"GET", "/admin/queue-summary", "tok-app", 403},
		{"GET", "/admin/queue-summary", "tok-ops", 200},
		{"POST", "/admin/reload-profiles", "tok-app", 403},
		{"GET", "/no/such/route", "tok-app", 403},
	} {
		if code, _ := a.do(c.method, c.path, c.token, nil); code != c.want {
			t.Errorf("%s %s (%q) = %d, want %d", c.method, c.path, c.token, code, c.want)
		}
	}
}

func TestRouteScope(t *testing.T) {
	for _, c := range []struct {
		method, path string
		want         Scope
	}{
		{"GET", "/healthz", scopeOpen}, {"HEAD", "/admin/backend-health", scopeOpen}, {"POST", "/admin/backend-health", ScopeAdmin},
		{"GET", "/metrics", ScopeMetrics}, {"POST", "/jobs", ScopeJobs}, {"GET", "/jobs/x", ScopeJobs},
		{"GET", "/debug/pprof/", ScopeAdmin}, {"GET", "/anything", ScopeAdmin},
	} {
		if got := RouteScope(c.method, c.path); got != c.want {
			t.Errorf("%s %s = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

func TestBearerToken(t *testing.T) {
	for h, want := range map[string]string{"Bearer abc": "abc", "bearer  abc ": "abc", "Basic abc": "", "Bearer ": "", "": ""} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if h != "" {
			r.Header.Set("Authorization", h)
		}
		if got, _ := bearerToken(r); got != want {
			t.Errorf("%q = %q, want %q", h, got, want)
		}
	}
}

func writeTokens(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tokens.yaml")
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func digest(tok string) string { d := sha256.Sum256([]byte(tok)); return hex.EncodeToString(d[:]) }

func TestLoadAuthenticator_RejectsBadFiles(t *testing.T) {
	ok := digest("x")
	for name, body := range map[string]string{
		"empty list":     "tokens: []\n",
		"no caller":      "tokens: [{sha256: " + ok + ", scopes: [jobs]}]\n",
		"short digest":   "tokens: [{caller: a, sha256: abc, scopes: [jobs]}]\n",
		"no scopes":      "tokens: [{caller: a, sha256: " + ok + "}]\n",
		"unknown scope":  "tokens: [{caller: a, sha256: " + ok + ", scopes: [root]}]\n",
		"shared digest":  "tokens: [{caller: a, sha256: " + ok + ", scopes: [jobs]}, {caller: b, sha256: " + ok + ", scopes: [jobs]}]\n",
		"unknown key":    "tokens: [{caller: a, sha256: " + ok + ", scopes: [jobs], token: plain}]\n",
		"not yaml":       "tokens: [",
		"oversized file": "# " + strings.Repeat("x", MaxTokensFileBytes) + "\ntokens: [{caller: a, sha256: " + ok + ", scopes: [jobs]}]\n",
	} {
		if _, err := LoadAuthenticator(writeTokens(t, body, 0o600)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, err := LoadAuthenticator(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file loaded")
	}
}

// A tokens file someone else could rewrite is refused: group- or world-writable, or a link.
func TestLoadAuthenticator_RefusesWritableOrForeignTokensFile(t *testing.T) {
	body := "tokens: [{caller: a, sha256: " + digest("x") + ", scopes: [jobs]}]\n"
	for _, mode := range []os.FileMode{0o620, 0o602} {
		if _, err := LoadAuthenticator(writeTokens(t, body, mode)); err == nil || !strings.Contains(err.Error(), "writable") {
			t.Errorf("mode %#o = %v", mode, err)
		}
	}
	target := writeTokens(t, body, 0o600)
	link := filepath.Join(t.TempDir(), "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthenticator(link); err == nil {
		t.Error("a symbolic link was followed")
	}
}

func TestAuthenticator_ReloadKeepsOldSetOnError(t *testing.T) {
	path := writeTokens(t, "tokens: [{caller: a, sha256: "+digest("tok-a")+", scopes: [jobs]}]\n", 0o600)
	a, err := LoadAuthenticator(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tokens: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Reload(); err == nil {
		t.Fatal("a broken file reloaded")
	}
	if a.authenticate("tok-a") == nil {
		t.Fatal("the old set was dropped")
	}
	if err := os.WriteFile(path, []byte("tokens: [{caller: b, sha256: "+digest("tok-b")+", scopes: [jobs]}]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Reload(); err != nil || a.authenticate("tok-a") != nil || a.authenticate("tok-b") == nil {
		t.Fatalf("rotation: %v", err)
	}
}

// Jobs are their submitter's: another caller's run id is a 404 on read and cancel, GET /jobs
// lists the caller's own, admin sees all, and a read token lists all but reads none.
func TestAuth_JobsAreOwnerScoped(t *testing.T) {
	a := newAPI(t, func(c *Config) {
		c.Auth = tokens(t, map[string][]string{"alice": {"jobs"}, "bob": {"jobs"}, "ops": {"admin"}, "hub": {"read"}})
	})
	_, mine, _ := a.submit("tok-alice", map[string]any{"agent_key": "watcher", "idempotency_key": "k"})
	a.submit("tok-bob", map[string]any{"agent_key": "watcher"})
	if j, _ := a.st.GetJob(mine.RunID); j.SubmittedBy != "alice" {
		t.Fatalf("owner = %q", j.SubmittedBy)
	}
	if code, _ := a.getJob("tok-bob", mine.RunID); code != http.StatusNotFound {
		t.Errorf("bob reads alice's job: %d", code)
	}
	if code, _ := a.do(http.MethodPost, "/jobs/"+mine.RunID+"/cancel", "tok-bob", nil); code != http.StatusNotFound {
		t.Errorf("bob cancels alice's job: %d", code)
	}
	if code, _ := a.getJob("tok-ops", mine.RunID); code != http.StatusOK {
		t.Errorf("admin reads: %d", code)
	}
	if code, _ := a.getJob("tok-hub", mine.RunID); code != http.StatusForbidden {
		t.Errorf("a read token reads a job: %d", code)
	}
	count := func(tok string) int {
		_, out := a.do(http.MethodGet, "/jobs", tok, nil)
		var r ListJobsResponse
		_ = json.Unmarshal(out, &r)
		return len(r.Jobs)
	}
	if count("tok-alice") != 1 || count("tok-ops") != 2 || count("tok-hub") != 2 {
		t.Errorf("lists: alice %d ops %d hub %d", count("tok-alice"), count("tok-ops"), count("tok-hub"))
	}
	if code, _ := a.do(http.MethodGet, "/admin/queue-summary", "tok-hub", nil); code != http.StatusOK {
		t.Errorf("a read token's queue summary: %d", code)
	}
	// Another caller's key neither finds nor blocks: bob's own submit with alice's key is new.
	if code, other, _ := a.submit("tok-bob", map[string]any{"agent_key": "watcher", "idempotency_key": "k"}); code != http.StatusCreated || other.RunID == mine.RunID {
		t.Errorf("bob's submit with alice's key = %d %+v", code, other)
	}
}

// The backend health's error text is for an admin only, with auth on.
func TestBackendHealth_RedactedUnlessAdmin(t *testing.T) {
	health := func(full bool) any { return map[string]any{"full": full} }
	a := newAPI(t, func(c *Config) {
		c.BackendHealth = health
		c.Auth = tokens(t, map[string][]string{"ops": {"admin"}, "app": {"jobs"}})
	})
	for tok, want := range map[string]string{"": "false", "bogus": "false", "tok-app": "false", "tok-ops": "true"} {
		code, out := a.do(http.MethodGet, "/admin/backend-health", tok, nil)
		if code != http.StatusOK || !strings.Contains(string(out), `"full":`+want) {
			t.Errorf("%q: %d %s", tok, code, out)
		}
	}
	b := newAPI(t, func(c *Config) { c.BackendHealth = health })
	if _, out := b.do(http.MethodGet, "/admin/backend-health", "", nil); !strings.Contains(string(out), `"full":true`) {
		t.Errorf("auth off: %s", out)
	}
}

// With auth off there are no callers: every job is everyone's.
func TestAuthDisabled_JobsVisibleToEveryone(t *testing.T) {
	a := newAPI(t, nil)
	_, ok, _ := a.submit("", map[string]any{"agent_key": "watcher"})
	if code, j := a.getJob("anything", ok.RunID); code != http.StatusOK || j.RunID != ok.RunID {
		t.Fatalf("read = %d", code)
	}
}

// A tokens file readable by its group (0640) is fine; one loosened after loading is refused on
// Reload, the loaded set kept; one in a directory others can write is refused.
func TestLoadAuthenticator_ModesAndItsDirectory(t *testing.T) {
	body := "tokens: [{caller: a, sha256: " + digest("tok-a") + ", scopes: [jobs]}]\n"
	path := writeTokens(t, body, 0o640)
	a, err := LoadAuthenticator(path)
	if err != nil {
		t.Fatalf("0640 = %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := a.Reload(); err == nil {
		t.Fatal("a loosened file reloaded")
	}
	if a.authenticate("tok-a") == nil {
		t.Fatal("the loaded set was dropped")
	}
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	open := filepath.Join(dir, "tokens.yaml")
	if err := os.WriteFile(open, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthenticator(open); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("a world-writable directory = %v", err)
	}
}

// A tokens file owned by another user is refused. Needs root, to give the file away.
func TestLoadAuthenticator_RefusesAForeignOwner(t *testing.T) {
	path := writeTokens(t, "tokens: [{caller: a, sha256: "+digest("tok-a")+", scopes: [jobs]}]\n", 0o600)
	if err := os.Chown(path, 4242, 4242); err != nil {
		t.Skip("chown to another user needs root")
	}
	if _, err := LoadAuthenticator(path); err == nil || !strings.Contains(err.Error(), "owned by uid 4242") {
		t.Fatalf("a foreign owner = %v", err)
	}
}
