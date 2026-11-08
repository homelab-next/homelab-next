// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"strings"
	"sync"
	"testing"

	"github.com/homelab-next/homelab-next/orchestrator/internal/profile"
)

func firstPicks(p *Policy, backends []Backend, n int) map[string]int {
	counts := map[string]int{}
	for i := 0; i < n; i++ {
		counts[p.pickOrder(backends)[0].Name]++
	}
	return counts
}

func TestPickOrder_WeightsSetTheShareOfFirstPicks(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "big", Weight: 2}, Backend{Name: "small", Weight: 1})
	counts := firstPicks(p, p.Backends, 300)
	if counts["big"] != 200 || counts["small"] != 100 {
		t.Errorf("first picks = %v, want 200:100 (weights 2:1)", counts)
	}
}

func TestPickOrder_EqualWeightsAlternate(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "a"}, Backend{Name: "b"})
	if first, second := p.pickOrder(p.Backends)[0].Name, p.pickOrder(p.Backends)[0].Name; first == second {
		t.Errorf("picked %q twice in a row", first)
	}
}

func TestPickOrder_AFreshPoolPicksTheFirstBackend(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "first"}, Backend{Name: "second"}, Backend{Name: "third"})
	order := p.pickOrder(p.Backends)
	if order[0].Name != "first" || order[1].Name != "second" || order[2].Name != "third" {
		t.Errorf("order = %v", order)
	}
}

func TestPickOrder_IsSafeForConcurrentCalls(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "big", Weight: 2}, Backend{Name: "small", Weight: 1})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.pickOrder(p.Backends)
		}()
	}
	wg.Wait()
	// 50 picks at 2:1 leave the totals where 50 sequential picks would.
	p2, _ := newPool(nil, p.Backends...)
	firstPicks(p2, p2.Backends, 50)
	if p.rrCurrent["big"] != p2.rrCurrent["big"] || p.rrCurrent["small"] != p2.rrCurrent["small"] {
		t.Errorf("totals %v after concurrent picks, %v sequentially", p.rrCurrent, p2.rrCurrent)
	}
}

// A backend left out of one call's eligible set keeps its total for the next.
func TestPickOrder_StateSurvivesChangingEligibleSets(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "big", Weight: 2}, Backend{Name: "small", Weight: 1})
	if got := p.pickOrder(p.Backends[:1]); got[0].Name != "big" {
		t.Fatalf("one-backend set picked %q", got[0].Name)
	}
	if counts := firstPicks(p, p.Backends, 300); counts["small"] < 90 {
		t.Errorf("first picks = %v after a narrower set; the totals were corrupted", counts)
	}
}

func TestEligible(t *testing.T) {
	p, _ := newPool(nil,
		Backend{Name: "big", Tags: []string{"general", "heavy"}, MaxContext: 131072},
		Backend{Name: "small", Tags: []string{"general", "light"}, MaxContext: 65536},
		Backend{Name: "unmeasured"},
	)
	names := func(a Affinity) string {
		var out []string
		for _, b := range p.eligible(a) {
			out = append(out, b.Name)
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct {
		name string
		a    Affinity
		want string
	}{
		{"no affinity: all, in order", Affinity{}, "big,small,unmeasured"},
		{"a required tag", Affinity{RequireTags: []string{"heavy"}}, "big"},
		{"every required tag", Affinity{RequireTags: []string{"heavy", "special"}}, ""},
		{"exclusion by name wins", Affinity{RequireTags: []string{"general"}, ExcludeBackends: []string{"small"}}, "big"},
		{"min context", Affinity{MinContext: 100000}, "big"},
		{"an unknown window fails closed", Affinity{MinContext: 1}, "big,small"},
		{"exclusive narrows nothing", Affinity{Exclusive: true}, "big,small,unmeasured"},
	} {
		if got := names(c.a); got != c.want {
			t.Errorf("%s: eligible = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestExplainEligibility(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "small", MaxContext: 33365})
	if found, ok, _ := p.ExplainEligibility("typo", Affinity{}); found || ok {
		t.Error("an unknown name was found")
	}
	if found, ok, reason := p.ExplainEligibility("small", Affinity{}); !found || !ok || reason != "" {
		t.Errorf("no affinity = %v, %v, %q", found, ok, reason)
	}
	found, ok, reason := p.ExplainEligibility("small", Affinity{MinContext: 131072})
	if !found || ok || !strings.Contains(reason, "33365") || !strings.Contains(reason, "131072") {
		t.Errorf("min context = %v, %v, %q (want both numbers named)", found, ok, reason)
	}
	if _, ok, reason := p.ExplainEligibility("small", Affinity{ExcludeBackends: []string{"small"}}); ok || !strings.Contains(reason, "excluded by name") {
		t.Errorf("exclusion = %v, %q", ok, reason)
	}
	if _, ok, reason := p.ExplainEligibility("small", Affinity{RequireTags: []string{"x"}}); ok || !strings.Contains(reason, "missing required tag") {
		t.Errorf("tags = %v, %q", ok, reason)
	}
}

func TestAffinityOfAProfileIsACopy(t *testing.T) {
	src := profile.BackendAffinity{RequireTags: []string{"a"}, ExcludeBackends: []string{"b"}, MinContext: 9, Exclusive: true}
	a := AffinityOf(src)
	src.RequireTags[0], src.ExcludeBackends[0] = "x", "y"
	if a.RequireTags[0] != "a" || a.ExcludeBackends[0] != "b" || a.MinContext != 9 || !a.Exclusive {
		t.Errorf("affinity = %+v", a)
	}
	if !(Affinity{Exclusive: true}).IsZero() || (Affinity{MinContext: 1}).IsZero() {
		t.Error("IsZero")
	}
}
