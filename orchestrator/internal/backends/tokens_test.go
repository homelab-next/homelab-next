// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/homelab-next/homelab-next/orchestrator/internal/scrape"
)

// An engine's metrics, as the tests' engines serve them: a 1,311,500-token pool given both as a
// size label and (over-reported) as blocks times block size.
const kvFmt = `engine:requests_running{engine="0"} 0.0
engine:cache_usage{engine="0",model_name="m"} %s
engine:cache_info{block_size="784",engine="0",inner_block_size="16",num_blocks="1681",pool_tokens="1311500"} 1.0
`

func kvBody(usage string) string { return fmt.Sprintf(kvFmt, usage) }

func reading(t *testing.T, body string) (pool, usage float64, ok bool) {
	t.Helper()
	samples, err := scrape.Parse(strings.NewReader(body), nil)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := newPool(nil)
	p.KV = testKV
	return p.engineReading(samples)
}

func TestEngineReading_PrefersThePoolLabelAndReadsUsage(t *testing.T) {
	if pool, usage, ok := reading(t, kvBody("0.25")); !ok || pool != 1311500 || usage != 0.25 {
		t.Errorf("pool, usage, ok = %v, %v, %v", pool, usage, ok)
	}
}

func TestEngineReading_FallsBackToBlocksTimesBlockSize(t *testing.T) {
	body := `engine:cache_info{block_size="16",engine="0",inner_block_size="8",num_blocks="1000"} 1.0` + "\n"
	if pool, _, ok := reading(t, body); !ok || pool != 16000 {
		t.Errorf("pool, ok = %v, %v; want 16000 (num_blocks x block_size, not inner_block_size)", pool, ok)
	}
}

func TestEngineReading_NoInfoMetricIsNoReading(t *testing.T) {
	if _, _, ok := reading(t, "engine:requests_running{} 1\n"); ok {
		t.Error("a reading without the info metric")
	}
}

func TestAdmitWeight_IsBoundedAndDefaultsToOne(t *testing.T) {
	for _, c := range []struct {
		p90, n int
		want   float64
	}{
		{0, 0, 1}, {57000, 0, 1}, {50000, 12, 50000.0 / 57000.0}, {57000, 5, 1}, {114000, 5, 2}, {900000, 5, 4}, {1000, 5, 0.5},
	} {
		if got := admitWeight(c.p90, c.n); got < c.want-1e-9 || got > c.want+1e-9 {
			t.Errorf("admitWeight(%d, %d) = %v, want %v", c.p90, c.n, got, c.want)
		}
	}
}

// twPool is one backend whose engine serves kvBody(usage), with token-weighted admission set to on.
func twPool(t *testing.T, usage string, on bool, maxConcurrent int, p90 map[string]int) (*Policy, *engine) {
	t.Helper()
	e := newEngine(t, func() string { return kvBody(usage) })
	p, _ := newPool(nil, Backend{Name: "engine", Weight: 1, MaxConcurrent: maxConcurrent, LoadProbeURLs: []string{e.URL}})
	p.LoadMetrics, p.KV, p.TokenWeightedAdmission = testLoadMetrics, testKV, on
	p.AgentPromptP90 = func(k string) (int, int) {
		if v, ok := p90[k]; ok {
			return v, 20
		}
		return 0, 0
	}
	return p, e
}

// The budget is 0.8 x 1,311,500 / 57,000 = 18.4 units: four weight-4 jobs fit (16), a fifth does not.
func TestReserve_TheTokenBudgetRefusesAndAReleaseRestores(t *testing.T) {
	p, _ := twPool(t, "0.0", true, 0, map[string]int{"big": 400000})
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if name, ok := p.Reserve(ctx, Affinity{}, fmt.Sprintf("r%d", i), "big"); !ok || name != "engine" {
			t.Fatalf("reservation %d = %q, %v", i, name, ok)
		}
	}
	if got := p.TokenReservedUnits("engine"); got != 16 {
		t.Fatalf("reserved = %v, want 16", got)
	}
	if _, ok := p.Reserve(ctx, Affinity{}, "r4", "big"); ok {
		t.Fatal("a fifth weight-4 job past the 18.4-unit budget")
	}
	if c := p.LastRefusalCause("r4"); c != CauseTokenBudget {
		t.Errorf("cause = %q", c)
	}
	if c := p.LastRefusalCause("r4"); c != "" {
		t.Errorf("the cause was not cleared: %q", c)
	}
	if _, ok := p.Reserve(ctx, Affinity{}, "small", "nohistory"); !ok {
		t.Error("a weight-1 job refused with 2.4 units left")
	}
	p.Release("engine", "r0")
	if got := p.TokenReservedUnits("engine"); got != 13 {
		t.Errorf("after a release = %v, want 13", got)
	}
	if _, ok := p.Reserve(ctx, Affinity{}, "r5", "big"); !ok {
		t.Error("a big job refused after a release freed 4 units")
	}
}

// Off: plain slot counting, no weight booked, no scrape for the token gate, no history asked for.
func TestReserve_TokenAdmissionOffIsPlainSlotCounting(t *testing.T) {
	p, e := twPool(t, "0.0", false, 0, map[string]int{"big": 400000})
	asked := 0
	p.AgentPromptP90 = func(string) (int, int) { asked++; return 400000, 20 }
	p.LoadMetrics = nil
	for i := 0; i < 10; i++ {
		if _, ok := p.Reserve(context.Background(), Affinity{}, fmt.Sprintf("r%d", i), "big"); !ok {
			t.Fatalf("reservation %d refused", i)
		}
	}
	if got := p.TokenReservedUnits("engine"); got != 0 || e.count() != 0 || asked != 0 {
		t.Errorf("units %v, scrapes %d, history lookups %d; want 0, 0, 0", got, e.count(), asked)
	}
}

func TestReserve_TheSlotCapIsStillCheckedFirst(t *testing.T) {
	p, _ := twPool(t, "0.0", true, 2, nil)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, ok := p.Reserve(ctx, Affinity{}, fmt.Sprintf("s%d", i), "a"); !ok {
			t.Fatalf("slot %d refused", i)
		}
	}
	if _, ok := p.Reserve(ctx, Affinity{}, "s2", "a"); ok {
		t.Fatal("admitted past max_concurrent 2")
	}
	if c := p.LastRefusalCause("s2"); c != CauseSlot {
		t.Errorf("cause = %q", c)
	}
}

// Traffic this pool did not send counts: 95% used leaves no room under an 80% budget.
func TestReserve_TheEnginesUsageIsAFloor(t *testing.T) {
	p, _ := twPool(t, "0.95", true, 0, nil)
	if _, ok := p.Reserve(context.Background(), Affinity{}, "x", "a"); ok {
		t.Error("admitted with the engine 95% used")
	}
	if c := p.LastRefusalCause("x"); c != CauseTokenBudget {
		t.Errorf("cause = %q", c)
	}
}

// A pool size that cannot be read skips the token gate: the slot cap alone applies.
func TestTokenBudget_FailsOpenWhenThePoolIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusInternalServerError) }))
	defer srv.Close()
	for name, b := range map[string]Backend{
		"an endpoint that fails": {Name: "engine", Weight: 1, LoadProbeURLs: []string{srv.URL}},
		"no probe":               {Name: "engine", Weight: 1},
	} {
		p, _ := newPool(nil, b)
		p.LoadMetrics, p.KV, p.TokenWeightedAdmission = testLoadMetrics, testKV, true
		if _, ok := p.Reserve(context.Background(), Affinity{}, "r", "a"); !ok {
			t.Errorf("%s: the token gate did not fail open", name)
		}
	}
}

// The last pool size known survives a failed read.
func TestEngineState_KeepsTheLastPoolAcrossAFailedRead(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			http.Error(w, "no", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(kvBody("0.1")))
	}))
	defer srv.Close()
	p, clk := newPool(nil, Backend{Name: "engine", LoadProbeURLs: []string{srv.URL}})
	p.KV = testKV
	b := p.Backends[0]
	if s := p.engineState(context.Background(), b); s.poolTokens != 1311500 {
		t.Fatalf("pool = %v", s.poolTokens)
	}
	fail.Store(true)
	clk.add(2 * engineSampleTTL)
	if s := p.engineState(context.Background(), b); s.poolTokens != 1311500 || s.usagePerc != 0 {
		t.Errorf("after a failed read: %+v", s)
	}
}

func TestHasRoomForAWeight_RespectsTheTokenBudget(t *testing.T) {
	p, _ := twPool(t, "0.0", true, 0, map[string]int{"big": 400000})
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if _, ok := p.Reserve(ctx, Affinity{}, fmt.Sprintf("h%d", i), "big"); !ok {
			t.Fatal("setup")
		}
	}
	b := p.Backends[0]
	if p.tokenBudgetAllows(ctx, b, p.weightFor("big")) {
		t.Error("a weight-4 job fits 16 of 18.4 units")
	}
	if !p.tokenBudgetAllows(ctx, b, p.weightFor("nohistory")) {
		t.Error("a weight-1 job does not fit 2.4 free units")
	}
}

func TestWeightFor_CachesTheHistoryLookups(t *testing.T) {
	calls := 0
	p, clk := newPool(nil)
	p.TokenWeightedAdmission = true
	p.AgentPromptP90 = func(string) (int, int) { calls++; return 114000, 9 }
	for i := 0; i < 5; i++ {
		if w := p.weightFor("agent"); w != 2 {
			t.Fatalf("weight = %v", w)
		}
	}
	clk.add(2 * weightCacheTTL)
	p.weightFor("agent")
	if calls != 2 {
		t.Errorf("history looked up %d times, want 2 (once, then once after the cache aged)", calls)
	}
}

// A token weight whose run holds no claim and is not live is returned by the reaper; a live run's
// is kept. A reaped claim gives its weight back.
func TestReapStaleReservations_ReturnsTokenWeights(t *testing.T) {
	p, _ := twPool(t, "0.0", true, 0, map[string]int{"big": 400000})
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if _, ok := p.Reserve(ctx, Affinity{}, fmt.Sprintf("dead-%d", i), "big"); !ok {
			t.Fatalf("setup %d", i)
		}
	}
	if got := p.ReapStaleReservations(map[string]bool{}, 0); len(got) != 4 {
		t.Fatalf("reaped = %v", got)
	}
	if u := p.TokenReservedUnits("engine"); u != 0 {
		t.Fatalf("the slots came back but %v units stayed reserved for dead runs", u)
	}
	for i := 0; i < 4; i++ {
		if _, ok := p.Reserve(ctx, Affinity{}, fmt.Sprintf("new-%d", i), "big"); !ok {
			t.Fatalf("an idle engine refused new run %d", i)
		}
	}
	q, _ := twPool(t, "0.0", true, 0, nil)
	q.recordTokenReservation("engine", "orphan", 2)
	q.recordTokenReservation("engine", "alive", 1)
	q.ReapStaleReservations(map[string]bool{"alive": true}, 0)
	if u := q.TokenReservedUnits("engine"); u != 1 {
		t.Fatalf("units = %v, want 1 (the orphan's 2 returned, the live run's 1 kept)", u)
	}
}

// A pool size that is not finite, or past any engine's, is no reading: never a budget that admits
// everything.
func TestEngineReading_AnAbsurdPoolIsNoReading(t *testing.T) {
	for name, body := range map[string]string{
		"blocks times block size overflows": `engine:cache_info{block_size="1e200",num_blocks="1e200"} 1` + "\n",
		"a pool label past any engine":      `engine:cache_info{pool_tokens="1e300"} 1` + "\n",
		"an infinite pool label":            `engine:cache_info{pool_tokens="+Inf"} 1` + "\n",
	} {
		if pool, _, ok := reading(t, body); ok {
			t.Errorf("%s: read a pool of %v", name, pool)
		}
	}
	big := newEngine(t, func() string { return `engine:cache_info{pool_tokens="6e11"} 1` + "\n" })
	p, _ := newPool(nil, Backend{Name: "engine", LoadProbeURLs: []string{big.URL, big.URL}})
	p.KV = testKV
	if s := p.engineState(context.Background(), p.Backends[0]); s.poolTokens != 0 {
		t.Errorf("two plausible engines summing past the bound read as %v", s.poolTokens)
	}
}
