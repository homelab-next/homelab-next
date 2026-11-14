// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/homelab-next/homelab-next/orchestrator/internal/backends"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

func TestEffectivePriority_MatchesSpecFormula(t *testing.T) {
	for _, c := range []struct {
		pri  int
		wait float64
		want int
	}{{50, 0, 50}, {50, 899, 50}, {50, 900, 45}, {50, 1800, 40}, {10, 9000, 1}, {1, 0, 1}} {
		if got := EffectivePriority(c.pri, c.wait); got != c.want {
			t.Errorf("EffectivePriority(%d, %v) = %d, want %d", c.pri, c.wait, got, c.want)
		}
	}
}

func TestPickNext_LowerEffectivePriorityWinsSeqTieBreaks(t *testing.T) {
	now := time.Now()
	old := &store.Job{RunID: "old", Priority: 60, Seq: 2, CreatedAt: now.Add(-3600 * time.Second)} // 60 - 20 = 40
	hi := &store.Job{RunID: "hi", Priority: 45, Seq: 1, CreatedAt: now}
	if got := PickNext([]*store.Job{hi, old}, now); got.RunID != "old" {
		t.Fatalf("picked %s, want the aged job", got.RunID)
	}
}

func TestPickNext_TieBreaksBySeqFIFO(t *testing.T) {
	now := time.Now()
	a := &store.Job{RunID: "a", Priority: 50, Seq: 7, CreatedAt: now}
	b := &store.Job{RunID: "b", Priority: 50, Seq: 3, CreatedAt: now}
	if got := PickNext([]*store.Job{a, b}, now); got.RunID != "b" {
		t.Fatalf("picked %s, want the earlier seq", got.RunID)
	}
}

func TestPickNext_EmptyCandidatesReturnsNil(t *testing.T) {
	if PickNext(nil, time.Now()) != nil {
		t.Fatal("non-nil from no candidates")
	}
}

// fixture failures, built from the pool's own sentinels and the runner's classes, as Call joins
// them.
func classed(c runner.Class) error { return runner.Wrap(c, errors.New("leg text")) }

func TestClassifyFailure(t *testing.T) {
	local := func(c runner.Class) *backends.Result { return &backends.Result{LocalClass: c} }
	cloud := func(l, c runner.Class) *backends.Result {
		return &backends.Result{LocalClass: l, CloudClass: c, UsedCloud: true}
	}
	cloudFailed := func(l, c runner.Class) error {
		return fmt.Errorf("%w (local: %w): %w", backends.ErrCloudFailed, classed(l), classed(c))
	}
	down := fmt.Errorf("%w (engine-a: probe): %w", backends.ErrBackendUnreachable, classed(runner.BackendFault))
	for name, c := range map[string]struct {
		err  error
		res  *backends.Result
		want string
	}{
		"job deadline":                {fmt.Errorf("%w: x", backends.ErrJobDeadline), local(runner.Internal), store.FailureDeadline},
		"turn cap stops":              {fmt.Errorf("%w: %w", backends.ErrTurnCapStops, classed(runner.TurnCap)), local(runner.TurnCap), store.FailureTurnCap},
		"ceiling local":               {fmt.Errorf("%w: %w", backends.ErrLocalOnly, classed(runner.TimeoutCeiling)), local(runner.TimeoutCeiling), store.FailureBudget},
		"ceiling local, cloud failed": {cloudFailed(runner.TimeoutCeiling, runner.TurnFailed), cloud(runner.TimeoutCeiling, runner.TurnFailed), store.FailureBudget},
		"stall local":                 {fmt.Errorf("%w: %w", backends.ErrLocalOnly, classed(runner.Stalled)), local(runner.Stalled), store.FailureStall},
		"stall in the cloud leg":      {cloudFailed(runner.BackendFault, runner.Stalled), cloud(runner.BackendFault, runner.Stalled), store.FailureStall},
		"stall local, cloud turn":     {cloudFailed(runner.Stalled, runner.TurnFailed), cloud(runner.Stalled, runner.TurnFailed), store.FailureHandlerError},
		"backend down":                {fmt.Errorf("%w: %w", backends.ErrLocalOnly, down), local(runner.BackendFault), store.FailureBackendDown},
		"no healthy backend":          {fmt.Errorf("%w: %w (x)", backends.ErrLocalOnly, backends.ErrNoHealthyBackend), local(runner.Internal), store.FailureBackendDown},
		"down local, cloud failed":    {fmt.Errorf("%w (local: %w): %w", backends.ErrCloudFailed, down, classed(runner.TurnFailed)), cloud(runner.BackendFault, runner.TurnFailed), store.FailureHandlerError},
		"concurrency limited":         {fmt.Errorf("%w: %w", backends.ErrConcurrencyLimited, classed(runner.ConcurrencyLimited)), local(runner.ConcurrencyLimited), store.FailureCapacity},
		"cloud concurrency limited":   {cloudFailed(runner.BackendFault, runner.ConcurrencyLimited), cloud(runner.BackendFault, runner.ConcurrencyLimited), store.FailureCapacity},
		"nothing attemptable":         {fmt.Errorf("%w: %w", backends.ErrLocalOnly, backends.ErrNoAttemptableBackend), local(runner.Internal), store.FailureCapacity},
		"killed by controller":        {fmt.Errorf("%w: %w", backends.ErrLocalOnly, classed(runner.KilledByController)), local(runner.KilledByController), store.FailureCapacity},
		"killed externally":           {fmt.Errorf("%w: %w", backends.ErrLocalOnly, classed(runner.KilledExternally)), local(runner.KilledExternally), store.FailureHandlerError},
		"turn failed":                 {fmt.Errorf("%w: %w", backends.ErrNotAttributable, classed(runner.TurnFailed)), local(runner.TurnFailed), store.FailureHandlerError},
		"no class":                    {errors.New("connection refused; timed out; stalled"), local(runner.Internal), store.FailureHandlerError},
		"own deadline":                {fmt.Errorf("lock wait: %w", context.DeadlineExceeded), local(runner.Internal), store.FailureTimeout},
		"no affinity match":           {fmt.Errorf("%w: %w", backends.ErrLocalOnly, backends.ErrNoLocalCapacity), local(runner.Internal), store.FailureHandlerError},
		"nil result":                  {classed(runner.Stalled), nil, store.FailureHandlerError},
	} {
		if got := ClassifyFailure(c.err, c.res); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

// A shutdown's cancelled context is capacity whatever the pool reported.
func TestClassify_ShutdownIsCapacity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := classify(ctx, fmt.Errorf("%w: x", backends.ErrJobDeadline), &backends.Result{}); got != store.FailureCapacity {
		t.Fatalf("class %q", got)
	}
	if got := classify(context.Background(), fmt.Errorf("%w: x", backends.ErrJobDeadline), &backends.Result{}); got != store.FailureDeadline {
		t.Fatalf("class %q", got)
	}
}

func TestMayRetryAttempt(t *testing.T) {
	ctx := context.Background()
	done, cancel := context.WithCancel(ctx)
	cancel()
	for name, c := range map[string]struct {
		ctx  context.Context
		err  error
		want bool
	}{
		"turn failed":       {ctx, classed(runner.TurnFailed), true},
		"deadline":          {ctx, fmt.Errorf("%w", backends.ErrJobDeadline), false},
		"ceiling":           {ctx, classed(runner.TimeoutCeiling), false},
		"turn cap":          {ctx, classed(runner.TurnCap), false},
		"turn cap stops":    {ctx, backends.ErrTurnCapStops, false},
		"ceiling in either": {ctx, fmt.Errorf("%w (local: %w): %w", backends.ErrCloudFailed, classed(runner.TimeoutCeiling), classed(runner.TurnFailed)), false},
		"context ended":     {done, classed(runner.TurnFailed), false},
	} {
		if got := mayRetryAttempt(c.ctx, c.err); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
		if c.ctx == ctx && mayAutoRequeue(c.err) != c.want {
			t.Errorf("%s: mayAutoRequeue disagrees", name)
		}
	}
}

func TestIsSignalKill(t *testing.T) {
	for c, want := range map[runner.Class]bool{runner.KilledByController: true, runner.KilledExternally: true, runner.TurnFailed: false, runner.Stalled: false} {
		if got := isSignalKill(classed(c), &backends.Result{LocalClass: c}); got != want {
			t.Errorf("%s: %v", c, got)
		}
	}
	cloudKill := fmt.Errorf("%w (local: %w): %w", backends.ErrCloudFailed, classed(runner.TurnFailed), classed(runner.KilledExternally))
	if !isSignalKill(cloudKill, &backends.Result{LocalClass: runner.TurnFailed, CloudClass: runner.KilledExternally}) {
		t.Error("a killed cloud leg is a kill")
	}
}

func TestClassReason(t *testing.T) {
	if got := classReason("stall", &backends.Result{LocalFailedReason: "stalled: no progress"}); got != "stall: stalled: no progress" {
		t.Errorf("reason = %q", got)
	}
	if got := classReason("capacity", nil); got != "capacity" {
		t.Errorf("reason = %q", got)
	}
}

func TestBoundText(t *testing.T) {
	if boundText("short", 10) != "short" {
		t.Fatal("a short text changed")
	}
	got := boundText(strings.Repeat("é", 100), 60)
	if len(got) > 60 || !utf8.ValidString(got) || !strings.HasSuffix(got, truncatedMarker) {
		t.Fatalf("bounded = %q (%d bytes)", got, len(got))
	}
	if got := boundText("abcdef", 3); got != truncatedMarker {
		t.Fatalf("a bound under the marker = %q", got)
	}
}

func TestNewRunID(t *testing.T) {
	a, b := NewRunID(), NewRunID()
	if len(a) != 32 || a == b || JobGatewayTag("", a) != a {
		t.Fatalf("run ids %q %q", a, b)
	}
}

func TestUsageFields_UnknownStaysUnknown(t *testing.T) {
	if _, ok := usageFields(nil); ok {
		t.Fatal("no report is no fields")
	}
	u, ok := usageFields(map[string]any{"completed": "yes", "cost_usd": "1", "cache_read_tokens": nil, "session_id": 5, "auxiliary": map[string]any{"by_task": map[string]any{"compress": 3.0}}})
	if !ok || u.Completed != nil || u.CostUSD != nil || u.CacheReadTokens != nil || u.SessionID != "" || u.AuxByTaskJSON != `{"compress":3}` {
		t.Fatalf("fields = %+v", u)
	}
	if c := usageTokenCounts(map[string]any{"input_tokens": -1.0, "output_tokens": float64(1 << 54), "api_calls": 2.0}); c.InputTokens != nil || c.OutputTokens != nil || *c.APICalls != 2 {
		t.Fatalf("counts = %+v", c)
	}
}

// A cache-read 0 alongside real prompt tokens is unknown unless the report vouches for its
// engine's cache count; a non-zero count, or a 0 with no prompt tokens, is kept.
func TestUsageFields_CacheReadZero(t *testing.T) {
	for name, c := range map[string]struct {
		usage   map[string]any
		unknown bool
	}{
		"0 with prompt tokens, unvouched": {map[string]any{"input_tokens": 100.0, "cache_read_tokens": 0.0}, true},
		"0 with prompt tokens, vouched":   {map[string]any{"input_tokens": 100.0, "cache_read_tokens": 0.0, "cache_read_reported": true}, false},
		"0 with no prompt tokens":         {map[string]any{"input_tokens": 0.0, "cache_read_tokens": 0.0}, false},
		"non-zero":                        {map[string]any{"input_tokens": 100.0, "cache_read_tokens": 40.0}, false},
	} {
		u, _ := usageFields(c.usage)
		if u.CacheReadUnknown != c.unknown {
			t.Errorf("%s: unknown = %v", name, u.CacheReadUnknown)
		}
	}
}

func TestUsageCallSizing(t *testing.T) {
	c, ok := usageCallSizing(map[string]any{"last_prompt_tokens": 900.0, "max_prompt_tokens": 1200.0, "max_tokens": 0.0})
	if !ok || *c.LastCallPromptTokens != 900 || *c.MaxCallPromptTokens != 1200 || c.MaxTokensRequested != nil {
		t.Fatalf("sizing = %+v", c)
	}
	if _, ok := usageCallSizing(map[string]any{"last_prompt_tokens": "9"}); ok {
		t.Fatal("a wrong type is unknown")
	}
}

func TestWaitCause_NoteTakeIsLastWinsAndConsumed(t *testing.T) {
	r := newRig(t, rigOptions{})
	r.sch.noteWaitCause("a", "slot")
	r.sch.noteWaitCause("a", "token_budget")
	r.sch.noteWaitCause("a", "")
	if got := r.sch.takeWaitCause("a"); got != "token_budget" {
		t.Fatalf("cause = %q", got)
	}
	if got := r.sch.takeWaitCause("a"); got != "" {
		t.Fatalf("taken twice: %q", got)
	}
}

// The call sizing and an unknown cache-read count reach the row.
func TestExecute_PersistsCallSizingAndUnknownCacheRead(t *testing.T) {
	usage := map[string]any{"input_tokens": 100.0, "cache_read_tokens": 0.0, "last_prompt_tokens": 90.0, "max_tokens": 4096.0}
	r := newRig(t, rigOptions{runner: newUsageRunner(usage), tweak: func(c *Config) { c.UsageDir = t.TempDir() }})
	r.submit("run-1", defaultProfile)
	r.tick()
	j := r.job("run-1")
	if j.Usage.CacheReadTokens != nil {
		t.Errorf("an unvouched cache-read 0 was stored as %d", *j.Usage.CacheReadTokens)
	}
	cs, err := r.st.GetCallSizing("run-1")
	if err != nil || cs.LastCallPromptTokens == nil || *cs.LastCallPromptTokens != 90 || *cs.MaxTokensRequested != 4096 {
		t.Fatalf("sizing = %+v, %v", cs, err)
	}
}

func newUsageRunner(usage map[string]any) runner.Runner {
	return runnerFunc(func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		b, _ := json.Marshal(usage)
		if err := os.WriteFile(s.UsagePath, b, 0o600); err != nil {
			return nil, err
		}
		return &runner.Result{Response: "ok", Usage: usage}, nil
	})
}

type runnerFunc func(ctx context.Context, s runner.Session) (*runner.Result, error)

func (f runnerFunc) Run(ctx context.Context, s runner.Session) (*runner.Result, error) {
	return f(ctx, s)
}

// Unknown is per session: one session that left a counter unknown makes the run's total
// unknown, and an unvouched cache-read 0 is judged with its own session's report.
func TestSumRunUsage_UnknownIsPerLeg(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, u map[string]any) {
		b, _ := json.Marshal(u)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("r.json", map[string]any{"input_tokens": 10.0, "output_tokens": 1.0, "cache_read_tokens": 0.0, "cost_usd": 0.1})
	write("r.leg2.json", map[string]any{"input_tokens": 5.0, "cache_read_tokens": 500.0, "cache_read_reported": true, "cost_usd": 0.2})
	write("other.json", map[string]any{"input_tokens": 1000.0})
	total, ok := sumRunUsage(dir, "r", map[string]any{"session_id": "s-2"})
	if !ok || total["input_tokens"] != 15.0 || total["output_tokens"] != nil || total["cache_read_tokens"] != nil ||
		total["cost_usd"] != 0.30000000000000004 && total["cost_usd"] != 0.3 || total["session_id"] != "s-2" {
		t.Fatalf("total = %v", total)
	}
	if u, _ := usageFields(total); u.CacheReadUnknown {
		t.Error("a summed report was judged again")
	}
	if _, ok := sumRunUsage(t.TempDir(), "r", nil); ok {
		t.Error("no file is no sum")
	}
}

func TestUsage_NegativeIsUnknown(t *testing.T) {
	if usageInt(map[string]any{"n": -1.0}, "n") != nil {
		t.Fatal("a negative counter is unknown")
	}
	if _, ok := usageCost(map[string]any{"cost_usd": -0.5}); ok {
		t.Fatal("a negative cost is unknown")
	}
	if v, ok := usageCost(map[string]any{"estimated_cost_usd": 0.0, "cost_usd": 9.0}); !ok || v != 0 {
		t.Fatal("estimated_cost_usd comes first")
	}
}

// A usage file that is not a regular file, or is too large, is no report.
func TestSumRunUsage_ReadsOnlyRegularBoundedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("/dev/zero", filepath.Join(dir, "r.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "r.a2.json"), []byte(strings.Repeat(" ", maxUsageFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := sumRunUsage(dir, "r", nil); ok {
		t.Fatal("a link or an oversized file was read")
	}
}

// A FIFO in the usage directory never blocks the sum, and a run with more usage files than any
// run could have is not summed.
func TestSumRunUsage_NeverBlocksAndIsBounded(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "r.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan bool, 1)
	go func() { _, ok := sumRunUsage(dir, "r", nil); done <- ok }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("a FIFO was read as a report")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the sum blocked on a FIFO")
	}
	many := t.TempDir()
	for i := 0; i < maxUsageSessions; i++ {
		if err := os.WriteFile(filepath.Join(many, fmt.Sprintf("r.a%d.json", i+2)), []byte(`{"input_tokens":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// more files than a run can have: the totals are unknown, never the last session's alone
	total, ok := sumRunUsage(many, "r", map[string]any{"input_tokens": 1.0, "cost_usd": 0.5, "session_id": "s-9"})
	if !ok || total["input_tokens"] != nil || total["cost_usd"] != nil || total["session_id"] != "s-9" {
		t.Fatalf("over the session bound: %v, %v", total, ok)
	}
}

// Each run's reports are in its own directory: a file another session wrote under another run's
// name, at the top of the usage directory or in its own run's directory, is not summed.
func TestUsage_ARunsSumReadsOnlyItsOwnDirectory(t *testing.T) {
	usage := map[string]any{"input_tokens": 10.0}
	dir := t.TempDir()
	r := newRig(t, rigOptions{runner: newUsageRunner(usage), tweak: func(c *Config) { c.UsageDir = dir }})
	forged := []byte(`{"input_tokens": 1000000}`)
	if err := os.WriteFile(filepath.Join(dir, "run-1.a9.json"), forged, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "run-other"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run-other", "run-1.a9.json"), forged, 0o600); err != nil {
		t.Fatal(err)
	}
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.InputTokens != 10 {
		t.Fatalf("input tokens %d: a file outside the run's own directory was summed", j.InputTokens)
	}
}

// Two queued jobs are the same work by their task's digest, never by text admission does not
// hold; a row without a digest is nobody's duplicate.
func TestKeyOf_ComparesTasksByDigest(t *testing.T) {
	a := &store.Job{RunID: "a", AgentKey: "watcher", SubmittedBy: "alice", TaskDescription: "one"}
	b := &store.Job{RunID: "b", AgentKey: "watcher", SubmittedBy: "alice", TaskDescription: "one"}
	c := &store.Job{RunID: "c", AgentKey: "watcher", SubmittedBy: "alice", TaskDescription: "two"}
	a.TaskSHA256, b.TaskSHA256, c.TaskSHA256 = "d1", "d1", "d2"
	b.TaskDescription = "" // admission's rows carry no text: the digest alone decides
	if keyOf(a) != keyOf(b) || keyOf(a) == keyOf(c) {
		t.Fatal("tasks are not compared by digest")
	}
	old1 := &store.Job{RunID: "o1", AgentKey: "watcher", SubmittedBy: "alice"}
	old2 := &store.Job{RunID: "o2", AgentKey: "watcher", SubmittedBy: "alice"}
	if keyOf(old1) == keyOf(old2) {
		t.Fatal("two rows without a digest were taken for one task")
	}
}
