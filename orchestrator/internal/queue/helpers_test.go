// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/backends"
	"github.com/homelab-next/homelab-next/orchestrator/internal/pathscope"
	"github.com/homelab-next/homelab-next/orchestrator/internal/profile"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner/runnertest"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// The queue's tests drive it through runnertest (scripted answers and classes, a session that
// blocks until released or cancelled) and, where a process must really die, through procRunner
// (proc_test.go), which runs this test binary as the session in its own process group.

// testZones is a fictional tree: owner/ is never writable, findings live under notes/findings/.
var testZones = func() pathscope.Zones {
	z, err := pathscope.NewZones(pathscope.Zones{
		DeniedRoots:   []string{"owner"},
		FindingsRoot:  "notes/findings/",
		SharedWrite:   []string{"inbox/"},
		ReservedNames: []string{"operator"},
	})
	if err != nil {
		panic(err)
	}
	return z
}()

func quiet(string, ...any) {}

// logLines collects a scheduler's log lines.
type logLines struct {
	mu    sync.Mutex
	lines []string
}

func (l *logLines) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logLines) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// rig is a scheduler over a real store and a real pool, with a scripted runner.
type rig struct {
	t      *testing.T
	st     *store.Store
	pool   *countingPool
	policy *backends.Policy
	run    runner.Runner
	sch    *Scheduler
	cfg    Config
	log    *logLines
}

// rigOptions shape a rig. Profiles maps agent key to the profile body after its id, agent key and
// toolsets lines.
type rigOptions struct {
	runner   runner.Runner
	backends []backends.Backend
	cloud    string // the cloud home; "" = none
	jobLimit time.Duration
	profiles map[string]string
	concur   int
	outbox   bool
	tweak    func(*Config)
	pool     func(*backends.Policy) // before Validate
}

const defaultProfile = "watcher"

func newRig(t *testing.T, o rigOptions) *rig {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "orch.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if o.outbox {
		st.EnableOutbox(OutboxEventBuilder("svc:orchestrator", "hnx/"), 0, nil)
	}
	if o.runner == nil {
		o.runner = runnertest.New()
	}
	if o.backends == nil {
		o.backends = []backends.Backend{{Name: "engine-a", Home: "home-a"}}
	}
	if o.profiles == nil {
		o.profiles = map[string]string{defaultProfile: ""}
	}
	policy := &backends.Policy{Runner: o.runner, Backends: o.backends, CloudHome: o.cloud, JobLimit: o.jobLimit, Log: quiet}
	if o.pool != nil {
		o.pool(policy)
	}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, st: st, policy: policy, pool: &countingPool{Pool: policy}, run: o.runner, log: &logLines{}}
	r.cfg = Config{
		Store:            st,
		Pool:             r.pool,
		Profiles:         loadProfiles(t, o.profiles),
		Contracts:        []string{},
		Concurrency:      max(o.concur, 1),
		GatewayTagPrefix: "hnx/",
		Log:              r.log.logf,
	}
	if o.tweak != nil {
		o.tweak(&r.cfg)
	}
	r.sch, err = New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	setRetryBackoff(t, time.Millisecond)
	return r
}

// loadProfiles writes one profile per agent key and loads them.
func loadProfiles(t *testing.T, profiles map[string]string) *profile.Registry {
	t.Helper()
	dir := t.TempDir()
	for key, extra := range profiles {
		body := "id: " + key + "-v1\nagent_key: " + key + "\ntoolsets: {real: \"notes,web\", shadow: notes}\n" + extra
		if err := os.WriteFile(filepath.Join(dir, key+".yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reg, err := profile.LoadRegistry(dir, profile.LoadOptions{Zones: testZones})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// submit stores a queued job of agent with run id id.
func (r *rig) submit(id, agent string) *store.Job {
	r.t.Helper()
	j := &store.Job{RunID: id, AgentKey: agent, Priority: 50, State: store.StateQueued,
		IdempotencyKey: "idem-" + id, CreatedAt: time.Now().UTC(), TaskDescription: "check the watched services"}
	if err := r.st.CreateJob(j); err != nil {
		r.t.Fatal(err)
	}
	return j
}

func (r *rig) tick() {
	r.t.Helper()
	if err := r.sch.Tick(context.Background()); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) job(id string) *store.Job {
	r.t.Helper()
	j, err := r.st.GetJob(id)
	if err != nil {
		r.t.Fatal(err)
	}
	return j
}

// waitState waits until run id reaches state.
func (r *rig) waitState(id string, state store.State) *store.Job {
	r.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		j := r.job(id)
		if j.State == state {
			return j
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("run %s is %s after 15s, want %s", id, j.State, state)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// tickAsync runs one Tick in its own goroutine; the returned channel closes when it returns.
func (r *rig) tickAsync(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := r.sch.Tick(ctx); err != nil {
			r.t.Error(err)
		}
	}()
	return done
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(15 * time.Second):
		t.Fatalf("%s did not happen in 15s", what)
	}
}

func setRetryBackoff(t *testing.T, d time.Duration) {
	prev := retryBackoff
	retryBackoff = func(int) time.Duration { return d }
	t.Cleanup(func() { retryBackoff = prev })
}

// countingPool counts every claim the queue takes and gives back, by run id: each Reserve or
// ReserveExclusive that succeeds must be paired with exactly one Release.
type countingPool struct {
	backends.Pool
	mu       sync.Mutex
	claims   map[string]int
	releases map[string]int
	reserves int
	calls    []string // the reserved argument of each Call
}

func (c *countingPool) Reserve(ctx context.Context, a backends.Affinity, runID, agentKey string) (string, bool) {
	b, ok := c.Pool.Reserve(ctx, a, runID, agentKey)
	c.note(runID, ok)
	return b, ok
}

func (c *countingPool) ReserveExclusive(ctx context.Context, a backends.Affinity, runID string) (string, bool) {
	b, ok := c.Pool.ReserveExclusive(ctx, a, runID)
	c.note(runID, ok)
	return b, ok
}

func (c *countingPool) note(runID string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reserves++
	if ok {
		if c.claims == nil {
			c.claims = map[string]int{}
		}
		c.claims[runID]++
	}
}

func (c *countingPool) Release(backend, runID string) {
	c.mu.Lock()
	if c.releases == nil {
		c.releases = map[string]int{}
	}
	c.releases[runID]++
	c.mu.Unlock()
	c.Pool.Release(backend, runID)
}

func (c *countingPool) Call(ctx context.Context, s runner.Session, l backends.Locality, a backends.Affinity, reserved string) (*backends.Result, error) {
	c.mu.Lock()
	c.calls = append(c.calls, reserved)
	c.mu.Unlock()
	return c.Pool.Call(ctx, s, l, a, reserved)
}

// balanced fails the test unless every claim was released exactly once and nothing else was.
func (c *countingPool) balanced(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := map[string]bool{}
	for id := range c.claims {
		ids[id] = true
	}
	for id := range c.releases {
		ids[id] = true
	}
	var sorted []string
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	for _, id := range sorted {
		if c.claims[id] != c.releases[id] {
			t.Errorf("run %s: %d claim(s), %d release(s)", id, c.claims[id], c.releases[id])
		}
	}
}

func (c *countingPool) claimCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, v := range c.claims {
		n += v
	}
	return n
}
