// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner/runnertest"
)

var exclusiveBig = Affinity{MinContext: 1_000_000, Exclusive: true}

func TestExclusive_DrainsThenLeasesAndBlocksOthers(t *testing.T) {
	ctx := context.Background()
	p, _ := newPool(nil, Backend{Name: "big", MaxContext: 1 << 20, MaxConcurrent: 8})
	if n, ok := p.Reserve(ctx, Affinity{}, "normal", ""); !ok || n != "big" {
		t.Fatalf("reserve = %q, %v", n, ok)
	}
	if b, ok := p.ReserveExclusive(ctx, exclusiveBig, "run-big"); ok {
		t.Fatalf("leased a busy backend: %q", b)
	}
	if b, ok := p.Reserve(ctx, Affinity{}, "normal-2", ""); ok {
		t.Fatalf("admitted to a draining backend: %q", b)
	}
	p.Release("big", "normal")
	b, ok := p.ReserveExclusive(ctx, exclusiveBig, "run-big")
	if !ok || b != "big" {
		t.Fatalf("the emptied backend was not leased: %q, %v", b, ok)
	}
	if _, ok := p.Reserve(ctx, Affinity{}, "normal-3", ""); ok {
		t.Fatal("admitted to a leased backend")
	}
	if _, ok := p.ReserveExclusive(ctx, exclusiveBig, "run-big"); ok {
		t.Fatal("leased twice")
	}
	p.Release(b, "run-big")
	if _, ok := p.Reserve(ctx, Affinity{}, "normal-4", ""); !ok {
		t.Fatal("still blocked after the owner released its lease")
	}
}

// The lease is measured from the probes when the backend has them, which see other callers' work:
// a backend busy with traffic the pool did not send is not leased.
func TestExclusive_ALeaseWaitsForTheProbeToReadEmpty(t *testing.T) {
	var running atomic.Int32
	running.Store(2)
	e := newEngine(t, func() string { return "engine:requests_running " + string(rune('0'+running.Load())) + "\n" })
	p, _ := newPool(nil, Backend{Name: "big", MaxContext: 1 << 20, LoadProbeURLs: []string{e.URL}})
	p.LoadMetrics = testLoadMetrics
	ctx := context.Background()
	if _, ok := p.ReserveExclusive(ctx, exclusiveBig, "run-big"); ok {
		t.Fatal("leased while the engine reports work")
	}
	running.Store(0)
	if b, ok := p.ReserveExclusive(ctx, exclusiveBig, "run-big"); !ok || b != "big" {
		t.Fatalf("not leased once empty: %q, %v", b, ok)
	}
}

func TestExclusive_AnUnrefreshedDrainLapses(t *testing.T) {
	ctx := context.Background()
	p, clk := newPool(nil, Backend{Name: "big", MaxContext: 1 << 20, MaxConcurrent: 8})
	if _, ok := p.Reserve(ctx, Affinity{}, "normal", ""); !ok {
		t.Fatal("reserve")
	}
	p.ReserveExclusive(ctx, exclusiveBig, "run-cancelled") // drains, then never asks again
	p.Release("big", "normal")
	clk.add(drainTTL + time.Second)
	if _, ok := p.Reserve(ctx, Affinity{}, "normal-2", ""); !ok {
		t.Fatal("an abandoned drain did not lapse")
	}
}

func TestExclusive_GivesUpAfterMaxWaitCoolsOffThenDrainsAgain(t *testing.T) {
	ctx := context.Background()
	p, clk := newPool(nil, Backend{Name: "big", MaxContext: 1 << 20, MaxConcurrent: 8})
	p.DrainMaxWait, p.DrainCooloff = 10*time.Minute, 5*time.Minute
	if _, ok := p.Reserve(ctx, Affinity{}, "forever", ""); !ok {
		t.Fatal("setup")
	}
	for i := 0; i < 11; i++ {
		p.ReserveExclusive(ctx, exclusiveBig, "run-big")
		clk.add(time.Minute)
	}
	p.ReserveExclusive(ctx, exclusiveBig, "run-big")
	if p.exclusivelyBlocked("big", "") {
		t.Fatal("the drain held past DrainMaxWait")
	}
	clk.add(time.Minute)
	p.ReserveExclusive(ctx, exclusiveBig, "run-big")
	if p.exclusivelyBlocked("big", "") {
		t.Fatal("drained again during the cool-off")
	}
	clk.add(5 * time.Minute)
	p.ReserveExclusive(ctx, exclusiveBig, "run-big")
	if !p.exclusivelyBlocked("big", "") {
		t.Fatal("did not drain again after the cool-off")
	}
}

func TestExclusive_OtherBackendsStillServeNormalWork(t *testing.T) {
	ctx := context.Background()
	p, _ := newPool(nil, Backend{Name: "big", MaxContext: 1 << 20, MaxConcurrent: 8}, Backend{Name: "small", MaxContext: 131072, MaxConcurrent: 4})
	if b, ok := p.ReserveExclusive(ctx, exclusiveBig, "run-big"); !ok || b != "big" {
		t.Fatalf("exclusive = %q, %v", b, ok)
	}
	if got, ok := p.Reserve(ctx, Affinity{}, "normal", ""); !ok || got != "small" {
		t.Fatalf("normal work = %q, %v", got, ok)
	}
}

// Call keeps an exclusive run on its lease, and keeps every other run's failover off it.
func TestExclusive_CallOrder(t *testing.T) {
	r := runnertest.New(runnertest.Fail(runner.BackendFault, "down"))
	p, _ := newPool(r, Backend{Name: "big", MaxContext: 1 << 20}, Backend{Name: "small", MaxContext: 131072})
	p.CloudHome = ""
	ctx := context.Background()
	if _, ok := p.ReserveExclusive(ctx, exclusiveBig, "run-big"); !ok {
		t.Fatal("lease")
	}
	if got := p.filterForExclusive([]Backend{{Name: "small"}, {Name: "big"}}, Affinity{}, "small", "run-other"); len(got) != 1 || got[0].Name != "small" {
		t.Fatalf("another run's order = %v", got)
	}
	if got := p.filterForExclusive([]Backend{{Name: "big"}, {Name: "small"}}, exclusiveBig, "big", "run-big"); len(got) != 1 || got[0].Name != "big" {
		t.Fatalf("the exclusive run's order = %v", got)
	}
	_, _ = p.Call(ctx, session("run-big"), CloudFallback, exclusiveBig, "big")
	_, _ = p.Call(ctx, session("run-other"), CloudFallback, Affinity{}, "")
	if got := targets(r); len(got) != 2 || got[0] != "big" || got[1] != "small" {
		t.Errorf("targets = %v, want big (the lease only), then small (never the leased big)", got)
	}
}

func TestExclusive_WithoutTheFlagNothingChanges(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "a"}, Backend{Name: "b"})
	if got := p.filterForExclusive([]Backend{{Name: "a"}, {Name: "b"}}, Affinity{}, "a", "r"); len(got) != 2 {
		t.Fatalf("filter = %v", got)
	}
}

// A run that died holding a lease gives it back to the reaper; a live run's is kept.
func TestExclusive_TheReaperReturnsADeadOwnersLeaseOnly(t *testing.T) {
	ctx := context.Background()
	p, _ := newPool(nil, Backend{Name: "a", Weight: 1, MaxConcurrent: 4})
	if _, ok := p.ReserveExclusive(ctx, Affinity{Exclusive: true}, "live"); !ok {
		t.Fatal("lease")
	}
	if got := p.ReapStaleReservations(map[string]bool{"live": true}, 0); len(got) != 0 || !p.exclusivelyBlocked("a", "") {
		t.Fatalf("a live run's lease was reaped: %v", got)
	}
	if got := p.ReapStaleReservations(map[string]bool{}, 0); len(got) != 1 || got[0] != "live" {
		t.Fatalf("reaped = %v", got)
	}
	if n := p.InFlight("a"); n != 0 {
		t.Fatalf("in flight = %d after the lease was reaped", n)
	}
	if _, ok := p.Reserve(ctx, Affinity{}, "other", ""); !ok {
		t.Fatal("the backend stayed leased to a dead run")
	}
}

// Only the owner's release clears a lease; a stray release returns nothing.
func TestExclusive_ReleaseIsOwnerChecked(t *testing.T) {
	ctx := context.Background()
	p, _ := newPool(nil, Backend{Name: "big", MaxContext: 1 << 20, MaxConcurrent: 8})
	if b, ok := p.ReserveExclusive(ctx, exclusiveBig, "run-big"); !ok || b != "big" {
		t.Fatalf("lease = %q, %v", b, ok)
	}
	p.Release("big", "run-other")
	p.Release("big", "")
	if !p.exclusivelyBlocked("big", "") || p.InFlight("big") != 1 {
		t.Fatalf("a release by another run cleared the lease (in flight %d)", p.InFlight("big"))
	}
	p.Release("big", "run-big")
	if p.exclusivelyBlocked("big", "") || p.InFlight("big") != 0 {
		t.Fatalf("the owner's release: blocked %v, in flight %d", p.exclusivelyBlocked("big", ""), p.InFlight("big"))
	}
}

// After the reaper cleared a dead run's lease and another run leased the backend, the dead run's
// late release frees neither the new lease nor a second slot.
func TestExclusive_ALateReleaseOfAReapedOwnerKeepsTheNewLease(t *testing.T) {
	ctx := context.Background()
	p, _ := newPool(nil, Backend{Name: "big", MaxContext: 1 << 20, MaxConcurrent: 8})
	if _, ok := p.ReserveExclusive(ctx, exclusiveBig, "run-a"); !ok {
		t.Fatal("lease run-a")
	}
	p.ReapStaleReservations(map[string]bool{}, 0)
	if b, ok := p.ReserveExclusive(ctx, exclusiveBig, "run-b"); !ok || b != "big" {
		t.Fatalf("run-b = %q, %v", b, ok)
	}
	p.Release("big", "run-a")
	if !p.exclusivelyBlocked("big", "") || p.InFlight("big") != 1 {
		t.Fatalf("the late release: blocked %v, in flight %d", p.exclusivelyBlocked("big", ""), p.InFlight("big"))
	}
}
