// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"context"
	"fmt"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// Admission against the slot cap: an unmeasured backend always admits, a measured one admits
// below its cap, a saturated one refuses (cause "slot"), and one backend with room among several is
// enough.
func TestReserve_TheSlotCap(t *testing.T) {
	ctx := context.Background()
	t.Run("unmeasured always admits", func(t *testing.T) {
		p, _ := newPool(nil, Backend{Name: "a", Tags: []string{"general"}})
		atomic.StoreInt64(p.inFlightCounter("a"), 100)
		if _, ok := p.Reserve(ctx, Affinity{RequireTags: []string{"general"}}, "r", ""); !ok {
			t.Error("an unmeasured backend refused")
		}
	})
	t.Run("the only eligible backend is at its cap", func(t *testing.T) {
		p, _ := newPool(nil, Backend{Name: "a", Tags: []string{"special"}, MaxContext: 131072, MaxConcurrent: 3})
		atomic.StoreInt64(p.inFlightCounter("a"), 3)
		if _, ok := p.Reserve(ctx, Affinity{RequireTags: []string{"special"}, MinContext: 100000}, "r", ""); ok {
			t.Error("admitted at the cap")
		}
		if c := p.LastRefusalCause("r"); c != CauseSlot {
			t.Errorf("cause = %q", c)
		}
	})
	t.Run("the only eligible backend has room", func(t *testing.T) {
		p, _ := newPool(nil, Backend{Name: "a", MaxConcurrent: 3})
		atomic.StoreInt64(p.inFlightCounter("a"), 2)
		if name, ok := p.Reserve(ctx, Affinity{}, "r", ""); !ok || name != "a" || p.InFlight("a") != 3 {
			t.Errorf("reserve = %q, %v (in flight %d)", name, ok, p.InFlight("a"))
		}
	})
	t.Run("one of several has room", func(t *testing.T) {
		p, _ := newPool(nil, Backend{Name: "full", MaxConcurrent: 8}, Backend{Name: "free", MaxConcurrent: 4})
		atomic.StoreInt64(p.inFlightCounter("full"), 8)
		atomic.StoreInt64(p.inFlightCounter("free"), 1)
		if name, ok := p.Reserve(ctx, Affinity{}, "r", ""); !ok || name != "free" {
			t.Errorf("reserve = %q, %v", name, ok)
		}
	})
	t.Run("nothing eligible is no claim and no cause", func(t *testing.T) {
		p, _ := newPool(nil, Backend{Name: "a", Tags: []string{"general"}, MaxConcurrent: 3})
		if _, ok := p.Reserve(ctx, Affinity{RequireTags: []string{"none"}}, "r", ""); ok {
			t.Error("a claim with nothing eligible")
		}
		if c := p.LastRefusalCause("r"); c != "" {
			t.Errorf("cause = %q: a permanent mismatch is no capacity refusal", c)
		}
		if !p.AnyHealthy(Affinity{RequireTags: []string{"none"}}) {
			t.Error("nothing eligible read as an outage")
		}
	})
	t.Run("no run id is refused", func(t *testing.T) {
		p, _ := newPool(nil, Backend{Name: "a"})
		if _, ok := p.Reserve(ctx, Affinity{}, "", ""); ok || p.InFlight("a") != 0 {
			t.Error("a claim nobody owns")
		}
	})
}

// Two reservations in one pass see each other at once.
func TestReserve_CountsTheSlotBeforeItReturns(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "a", MaxConcurrent: 3})
	ctx := context.Background()
	var got []bool
	for i := 0; i < 4; i++ {
		_, ok := p.Reserve(ctx, Affinity{}, fmt.Sprintf("r%d", i), "")
		got = append(got, ok)
	}
	if fmt.Sprint(got) != "[true true true false]" {
		t.Errorf("admissions = %v", got)
	}
}

// A reservation whose run is no longer live is reaped after the grace; the late release of the
// same run returns nothing more.
func TestReapStaleReservations_ReturnsALeakedSlotOnce(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "a", Weight: 1, MaxConcurrent: 1})
	ctx := context.Background()
	if n, ok := p.Reserve(ctx, Affinity{}, "run-1", "x"); !ok || n != "a" {
		t.Fatalf("reserve = %q, %v", n, ok)
	}
	if got := p.ReapStaleReservations(map[string]bool{"run-1": true}, 0); len(got) != 0 {
		t.Fatalf("a live run was reaped: %v", got)
	}
	if got := p.ReapStaleReservations(map[string]bool{}, time.Hour); len(got) != 0 {
		t.Fatalf("reaped inside the grace: %v", got)
	}
	if got := p.ReapStaleReservations(map[string]bool{}, 0); len(got) != 1 || got[0] != "run-1" {
		t.Fatalf("reaped = %v", got)
	}
	if _, ok := p.Reserve(ctx, Affinity{}, "run-2", "x"); !ok {
		t.Fatal("the reaper did not return the slot")
	}
	p.Release("a", "run-1")
	if _, ok := p.Reserve(ctx, Affinity{}, "run-3", "x"); ok {
		t.Fatal("a double release admitted past max_concurrent 1")
	}
}

func TestReapStaleReservations_AReReservedRunReleases(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "a", Weight: 1, MaxConcurrent: 1})
	ctx := context.Background()
	if _, ok := p.Reserve(ctx, Affinity{}, "run-1", "x"); !ok {
		t.Fatal("reserve")
	}
	p.ReapStaleReservations(map[string]bool{}, 0)
	if _, ok := p.Reserve(ctx, Affinity{}, "run-1", "x"); !ok {
		t.Fatal("re-reserve under the same run id")
	}
	p.Release("a", "run-1")
	if _, ok := p.Reserve(ctx, Affinity{}, "run-2", "x"); !ok {
		t.Fatal("slot leaked: the re-reserved run's release was skipped")
	}
}

func TestReapStaleReservations_PrunesOldReapedEntries(t *testing.T) {
	p, clk := newPool(nil, Backend{Name: "a", Weight: 1, MaxConcurrent: 4})
	if _, ok := p.Reserve(context.Background(), Affinity{}, "run-1", ""); !ok {
		t.Fatal("reserve")
	}
	p.ReapStaleReservations(map[string]bool{}, 0)
	if len(p.reaped) != 1 {
		t.Fatalf("reaped = %v", p.reaped)
	}
	clk.add(2 * time.Hour)
	p.ReapStaleReservations(map[string]bool{}, 0)
	if len(p.reaped) != 0 {
		t.Fatalf("reaped grows without bound: %v", p.reaped)
	}
}

// Refusal causes a run never reads are bounded.
func TestSetRefusal_IsBounded(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "a", Weight: 1, MaxConcurrent: 1})
	ctx := context.Background()
	if _, ok := p.Reserve(ctx, Affinity{}, "holder", ""); !ok {
		t.Fatal("reserve")
	}
	for i := 0; i < maxRefusals+100; i++ {
		if _, ok := p.Reserve(ctx, Affinity{}, "q-"+strconv.Itoa(i), ""); ok {
			t.Fatal("over-admitted")
		}
	}
	if n := len(p.twRefusal); n > maxRefusals {
		t.Fatalf("%d refusal causes held, want at most %d", n, maxRefusals)
	}
}

// PrimaryFirst: the primary takes every job up to its cap, the backup the overflow.
func TestReserve_PrimaryFirstOverflowsInOrder(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "primary", Weight: 2, MaxConcurrent: 3}, Backend{Name: "backup", Weight: 1, MaxConcurrent: 2})
	p.PrimaryFirst = true
	var got []string
	for i := 0; i < 6; i++ {
		name, ok := p.Reserve(context.Background(), Affinity{}, fmt.Sprintf("r%d", i), "a")
		if !ok {
			name = "refused"
		}
		got = append(got, name)
	}
	if fmt.Sprint(got) != "[primary primary primary backup backup refused]" {
		t.Fatalf("picks = %v", got)
	}
}

// A release under a run id that holds no claim returns nothing, so it can never drive a count
// negative and over-admit.
func TestRelease_OnlyTheRunsOwnClaim(t *testing.T) {
	p, clk := newPool(nil, Backend{Name: "a", Weight: 1, MaxConcurrent: 1})
	ctx := context.Background()
	if _, ok := p.Reserve(ctx, Affinity{}, "run-1", ""); !ok {
		t.Fatal("reserve")
	}
	p.Release("a", "stray")
	p.Release("a", "")
	if n := p.InFlight("a"); n != 1 {
		t.Fatalf("in flight = %d after stray releases, want 1", n)
	}
	p.ReapStaleReservations(map[string]bool{}, 0)
	clk.add(2 * reapedRetention)
	p.ReapStaleReservations(map[string]bool{}, 0)
	if _, ok := p.Reserve(ctx, Affinity{}, "run-2", ""); !ok {
		t.Fatal("the reaper did not return the slot")
	}
	p.Release("a", "run-1") // very late, after its reaped entry was pruned
	if n := p.InFlight("a"); n != 1 {
		t.Fatalf("in flight = %d, want 1 (run-2's)", n)
	}
	if _, ok := p.Reserve(ctx, Affinity{}, "run-3", ""); ok {
		t.Fatal("a double release admitted past max_concurrent 1")
	}
}

// A release naming the wrong backend releases the claim's own.
func TestRelease_ReleasesTheClaimsOwnBackend(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "a"}, Backend{Name: "b"})
	if n, ok := p.Reserve(context.Background(), Affinity{ExcludeBackends: []string{"b"}}, "run-1", ""); !ok || n != "a" {
		t.Fatal("reserve")
	}
	p.Release("b", "run-1")
	if p.InFlight("a") != 0 || p.InFlight("b") != 0 {
		t.Errorf("a=%d b=%d", p.InFlight("a"), p.InFlight("b"))
	}
}

// One claim per run id, on any backend and by either reserve path.
func TestReserve_OneClaimPerRunID(t *testing.T) {
	ctx := context.Background()
	for _, winner := range []string{"a", "b"} {
		other := map[string]string{"a": "b", "b": "a"}[winner]
		p, _ := newPool(nil, Backend{Name: "a", Weight: 1, MaxConcurrent: 4, MaxContext: 1 << 20}, Backend{Name: "b", Weight: 1, MaxConcurrent: 4, MaxContext: 1 << 20})
		p.TokenWeightedAdmission = true
		if n, ok := p.Reserve(ctx, Affinity{ExcludeBackends: []string{other}}, "run-x", ""); !ok || n != winner {
			t.Fatalf("first reserve = %q, %v", n, ok)
		}
		if n, ok := p.Reserve(ctx, Affinity{ExcludeBackends: []string{winner}}, "run-x", ""); ok {
			t.Fatalf("a second claim under the same run id: %q", n)
		}
		if n, ok := p.ReserveExclusive(ctx, Affinity{Exclusive: true, ExcludeBackends: []string{winner}}, "run-x"); ok {
			t.Fatalf("a lease for a run that holds a claim: %q", n)
		}
		if p.exclusivelyBlocked(other, "") {
			t.Fatalf("a run holding a claim started draining %s", other)
		}
		if p.InFlight(winner) != 1 || p.InFlight(other) != 0 {
			t.Fatalf("%s=%d %s=%d, want 1 and 0", winner, p.InFlight(winner), other, p.InFlight(other))
		}
		p.Release(winner, "run-x")
		if p.InFlight("a") != 0 || p.InFlight("b") != 0 || p.TokenReservedUnits(winner) != 0 {
			t.Fatalf("after release a=%d b=%d units=%v", p.InFlight("a"), p.InFlight("b"), p.TokenReservedUnits(winner))
		}
		if _, ok := p.Reserve(ctx, Affinity{}, "run-x", ""); !ok {
			t.Fatal("a released run id cannot reserve again")
		}
	}
}
