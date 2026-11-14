// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner/runnertest"
)

// The pool's tests drive it through runnertest: every failure class, an answer check and a
// session that blocks until released or cancelled, with no process started. What a runner does
// inside a session (spawning, stall detection, reading its own failure text) is the runner's, and
// is tested where the runner lives.

// fakeClock is the pool's clock in a test.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func quiet(string, ...any) {}

// newPool is a pool over backends with r as its runner (an answering runnertest.Runner when nil),
// a cloud home, a fake clock and no log output.
func newPool(r runner.Runner, backends ...Backend) (*Policy, *fakeClock) {
	if r == nil {
		r = runnertest.New()
	}
	c := &fakeClock{t: time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)}
	return &Policy{Runner: r, Backends: backends, CloudHome: "cloud-home", Log: quiet, now: c.now}, c
}

func session(runID string) runner.Session {
	return runner.Session{RunID: runID, AgentKey: "watcher", Prompt: "p", Toolsets: []string{"t"}, UsagePath: "/u/" + runID + ".json"}
}

// The engine metric names the tests' engines serve; nothing in the pool names them.
var (
	testLoadMetrics = []string{"engine:requests_running", "engine:requests_waiting"}
	testKV          = KVMetrics{Info: "engine:cache_info", PoolLabel: "pool_tokens", BlocksLabel: "num_blocks", BlockSizeLabel: "block_size", Usage: "engine:cache_usage"}
)

// engine serves body() as its metrics, counting the requests.
type engine struct {
	*httptest.Server
	mu   sync.Mutex
	hits int
}

func newEngine(t *testing.T, body func() string) *engine {
	t.Helper()
	e := &engine{}
	e.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.hits++
		e.mu.Unlock()
		_, _ = w.Write([]byte(body()))
	}))
	t.Cleanup(e.Close)
	return e
}

func (e *engine) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.hits
}

// deadURL is a URL nothing listens on any more.
func deadURL(t *testing.T) string {
	t.Helper()
	s := httptest.NewServer(http.NotFoundHandler())
	u := s.URL
	s.Close()
	return u
}
