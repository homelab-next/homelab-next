// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

const loadBody = `# TYPE engine:requests_running gauge
engine:requests_running{engine="0",model_name="m"} 5.0
engine:requests_waiting{engine="0",model_name="m"} 8.0
engine:other{engine="0"} 100
`

// The load is the named gauges summed over every probe URL (one per engine).
func TestCurrentLoad_SumsTheLoadMetricsOverEveryProbe(t *testing.T) {
	e1 := newEngine(t, func() string { return loadBody })
	e2 := newEngine(t, func() string { return "engine:requests_running 2\n" })
	p, _ := newPool(nil)
	p.LoadMetrics = testLoadMetrics
	if got := p.currentLoad(context.Background(), Backend{Name: "a", LoadProbeURLs: []string{e1.URL, e2.URL}}); got != 15 {
		t.Errorf("load = %d, want 15 (5 + 8 + 2)", got)
	}
}

// A probe that cannot be read, or reads none of the metrics, is no reading: the pool's own count
// stands, never zero.
func TestCurrentLoad_AnUnreadableProbeFallsBackToTheOwnCount(t *testing.T) {
	html := newEngine(t, func() string { return "<html>not metrics</html>" })
	for name, url := range map[string]string{"dead": deadURL(t), "not metrics": html.URL} {
		p, _ := newPool(nil)
		p.LoadMetrics = testLoadMetrics
		b := Backend{Name: "a", MaxConcurrent: 8, LoadProbeURLs: []string{url}}
		atomic.StoreInt64(p.inFlightCounter("a"), 3)
		if got := p.loadRatio(context.Background(), b); got != 3.0/8.0 {
			t.Errorf("%s: ratio = %v, want 3/8", name, got)
		}
	}
}

// No load metric named: nothing is fetched, the own count stands (Validate refuses that set-up).
func TestCurrentLoad_WithoutLoadMetricsFetchesNothing(t *testing.T) {
	e := newEngine(t, func() string { return loadBody })
	p, _ := newPool(nil)
	if got := p.currentLoad(context.Background(), Backend{Name: "a", LoadProbeURLs: []string{e.URL}}); got != 0 || e.count() != 0 {
		t.Errorf("load = %d, probe hits = %d", got, e.count())
	}
}

func TestLoadRatio_AnUnmeasuredBackendIsAlwaysZero(t *testing.T) {
	p, _ := newPool(nil)
	atomic.StoreInt64(p.inFlightCounter("a"), 50)
	if got := p.loadRatio(context.Background(), Backend{Name: "a"}); got != 0 {
		t.Errorf("ratio = %v", got)
	}
}

func TestLoadRatio_UsesTheOwnCountWithoutAProbe(t *testing.T) {
	p, _ := newPool(nil)
	atomic.StoreInt64(p.inFlightCounter("a"), 2)
	if got := p.loadRatio(context.Background(), Backend{Name: "a", MaxConcurrent: 4}); got != 0.5 {
		t.Errorf("ratio = %v, want 0.5", got)
	}
}

// The probe sees other callers' traffic too: it wins when higher; the own count wins when the probe
// lags behind it.
func TestLoadRatio_TakesTheLargerOfProbeAndOwnCount(t *testing.T) {
	e := newEngine(t, func() string { return "engine:requests_running 6\nengine:requests_waiting 2\n" })
	p, _ := newPool(nil)
	p.LoadMetrics = testLoadMetrics
	b := Backend{Name: "a", MaxConcurrent: 8, LoadProbeURLs: []string{e.URL}}
	atomic.StoreInt64(p.inFlightCounter("a"), 1)
	if got := p.loadRatio(context.Background(), b); got != 1.0 {
		t.Errorf("ratio = %v, want 1 (the probe's 8)", got)
	}
	atomic.StoreInt64(p.inFlightCounter("a"), 12)
	if got := p.loadRatio(context.Background(), b); got != 1.5 {
		t.Errorf("ratio = %v, want 1.5 (the own 12)", got)
	}
}

// A saturated backend goes after an idle one, whatever the weights say.
func TestSelectOrder_PrefersTheLeastLoadedBackend(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "big", Weight: 2, MaxConcurrent: 8}, Backend{Name: "small", Weight: 1, MaxConcurrent: 4})
	atomic.StoreInt64(p.inFlightCounter("big"), 10)
	if order := p.selectOrder(context.Background(), p.Backends); order[0].Name != "small" {
		t.Errorf("order = %v, want small first (big is 10/8, small 0/4)", order)
	}
}

// With nothing measured every ratio is 0, so the round-robin's order stands exactly.
func TestSelectOrder_TiesKeepTheRoundRobin(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "big", Weight: 2}, Backend{Name: "small", Weight: 1})
	counts := map[string]int{}
	for i := 0; i < 300; i++ {
		counts[p.selectOrder(context.Background(), p.Backends)[0].Name]++
	}
	if counts["big"] != 200 || counts["small"] != 100 {
		t.Errorf("first picks = %v, want 200:100", counts)
	}
}

// PrimaryFirst keeps the configured order, and never returns the pool's own slice.
func TestSelectOrder_PrimaryFirstKeepsTheConfiguredOrder(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "primary", Weight: 1}, Backend{Name: "backup", Weight: 9, MaxConcurrent: 1})
	p.PrimaryFirst = true
	atomic.StoreInt64(p.inFlightCounter("primary"), 100)
	order := p.selectOrder(context.Background(), p.Backends)
	if order[0].Name != "primary" {
		t.Errorf("order = %v", order)
	}
	order[0].Name = "changed"
	if p.Backends[0].Name != "primary" {
		t.Error("selectOrder returned the pool's own backing array")
	}
}

func TestInFlightSnapshot(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "a"}, Backend{Name: "b"})
	for _, id := range []string{"r2", "r1"} {
		if _, ok := p.Reserve(context.Background(), Affinity{ExcludeBackends: []string{"b"}}, id, ""); !ok {
			t.Fatal("reserve")
		}
	}
	snap := p.InFlightSnapshot()
	if a := snap["a"]; a.InFlight != 2 || len(a.ReservedRuns) != 2 || a.ReservedRuns[0] != "r1" {
		t.Errorf("snapshot = %+v", snap)
	}
}

// A load reading that is not a finite, non-negative count is no reading; a huge one reads as full,
// never as a wrapped integer that looks idle.
func TestCurrentLoad_RejectsNonFiniteAndNegativeAndClampsHuge(t *testing.T) {
	for _, c := range []struct {
		value string
		want  float64
	}{{"1e300", 1}, {"-5", 0.5}, {"+Inf", 0.5}, {"NaN", 0.5}} {
		e := newEngine(t, func() string { return "engine:requests_running " + c.value + "\n" })
		p, _ := newPool(nil)
		p.LoadMetrics = testLoadMetrics
		atomic.StoreInt64(p.inFlightCounter("a"), 2)
		got := p.loadRatio(context.Background(), Backend{Name: "a", MaxConcurrent: 4, LoadProbeURLs: []string{e.URL}})
		if (c.want == 1 && got < 1) || (c.want != 1 && got != c.want) {
			t.Errorf("%s: ratio %v, want %v", c.value, got, c.want)
		}
	}
}

// One admission decision reads each probe URL once at most, however many checks it makes (the
// order's ratios, the slot cap, the token budget), and reads the backends concurrently; the next
// decision inside sampleTTL reads none. A probe that hangs costs one timeout, and, as in the
// private controller, its backend falls back to the pool's own count, so it can still admit.
func TestReserve_ReadsEachProbeOnceAndATarpitOnlyOnce(t *testing.T) {
	stop := make(chan struct{})
	tarpit := newEngine(t, func() string { <-stop; return "" })
	t.Cleanup(func() { close(stop) })
	other := newEngine(t, func() string {
		return "engine:requests_running 0\n" + `engine:cache_info{pool_tokens="1000000"} 1` + "\n"
	})
	p, clk := newPool(nil,
		Backend{Name: "slow", MaxConcurrent: 4, LoadProbeURLs: []string{tarpit.URL}},
		Backend{Name: "fast", MaxConcurrent: 4, LoadProbeURLs: []string{other.URL}},
		Backend{Name: "slow-too", MaxConcurrent: 4, LoadProbeURLs: []string{tarpit.URL + "/2"}},
	)
	p.LoadMetrics, p.KV, p.TokenWeightedAdmission = testLoadMetrics, testKV, true
	p.ProbeTimeout = 200 * time.Millisecond
	ctx := context.Background()
	start := time.Now()
	name, ok := p.Reserve(ctx, Affinity{}, "run-1", "agent")
	elapsed := time.Since(start)
	if !ok {
		t.Fatal("refused: a hanging probe falls back to the own count")
	}
	if tarpit.count() != 2 || other.count() != 1 {
		t.Errorf("fetches: tarpit %d (want 2, one per URL), fast %d (want 1)", tarpit.count(), other.count())
	}
	if elapsed > 2*time.Second {
		t.Errorf("one decision took %v against two hanging probes", elapsed)
	}
	p.Release(name, "run-1")
	if _, ok := p.Reserve(ctx, Affinity{}, "run-2", "agent"); !ok || tarpit.count() != 2 || other.count() != 1 {
		t.Errorf("a second decision inside the window fetched again: tarpit %d, fast %d", tarpit.count(), other.count())
	}
	clk.add(2 * sampleTTL)
	p.Reserve(ctx, Affinity{}, "run-3", "agent")
	if other.count() != 2 {
		t.Errorf("a decision after the window did not read again: fast %d", other.count())
	}
}
