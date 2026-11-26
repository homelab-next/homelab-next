// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"sort"
	"sync/atomic"
)

// tier is the deployments of one role that share a priority. They are balanced: each request
// tries first the member with the fewest attempts in flight, ties broken by a rotating start so
// sequential requests (all counts zero) still spread evenly; the other members follow in the
// same order, so a failed attempt moves on within the tier before the next tier is tried.
type tier struct {
	deps []*Deployment
	next atomic.Uint64
}

// tierList groups the role's deployments: a deployment with no priority is its own tier, in list
// order (strict failover, as before priorities existed); deployments with a priority form one
// tier per distinct value, lowest value first. Validation makes a role all one or all the other.
func (r *Role) tierList() []*tier {
	r.tierOnce.Do(func() {
		deps := nonNil(r)
		if len(deps) > 0 && deps[0].Priority == 0 {
			for _, d := range deps {
				r.tiers = append(r.tiers, &tier{deps: []*Deployment{d}})
			}
			return
		}
		byPrio := map[int]*tier{}
		for _, d := range deps {
			t := byPrio[d.Priority]
			if t == nil {
				t = &tier{}
				byPrio[d.Priority] = t
				r.tiers = append(r.tiers, t)
			}
			t.deps = append(t.deps, d)
		}
		sort.SliceStable(r.tiers, func(i, j int) bool { return r.tiers[i].deps[0].Priority < r.tiers[j].deps[0].Priority })
	})
	return r.tiers
}

// order returns the tier's deployments in the order to try them for one request.
func (t *tier) order() []*Deployment {
	n := len(t.deps)
	if n == 1 {
		return t.deps
	}
	start := int((t.next.Add(1) - 1) % uint64(n))
	out := make([]*Deployment, n)
	load := make(map[*Deployment]int64, n)
	for i := range out {
		d := t.deps[(start+i)%n]
		out[i] = d
		load[d] = d.inflight.Load()
	}
	sort.SliceStable(out, func(i, j int) bool { return load[out[i]] < load[out[j]] })
	return out
}
