// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"context"
	"time"
)

// Exclusive leases. An engine's KV cache is one pool every running request shares, so a request
// that needs most of it can run safely only on an otherwise empty engine; admitted beside normal
// traffic it would push the others out and have them recomputed. A slot count cannot say that: a
// big job and a small one take one slot each. A profile with backend_affinity.exclusive asks for
// the backend alone (its min_context still decides which backends qualify). The scheduler calls
// ReserveExclusive once per pass while the job is queued:
//
//  1. drain: the first call marks the chosen backend draining for the run; from then on no other
//     job is admitted to it and no other run's failover lands on it;
//  2. lease: once its measured load (the probes, which see other callers too, else the pool's own
//     count) is 0, the drain becomes a lease, recorded as the run's claim, and the job is admitted;
//     Call keeps it on that one backend (the cloud leg still applies);
//  3. release: Release with the lease's own run id clears it; nobody else's does. The reaper clears
//     the lease of a run that died holding it.
//
// So that a lease can never wedge a backend: a drain nobody refreshes (the queued job was
// cancelled) lapses after drainTTL; a backend that never empties is let go after DrainMaxWait, and
// the run cools off for DrainCooloff, so normal work flows, before it drains again.

const (
	drainTTL            = 2 * time.Minute
	defaultDrainMaxWait = 30 * time.Minute
	defaultDrainCooloff = 30 * time.Minute
)

type exclusiveState struct {
	runID      string
	held       bool
	drainStart time.Time
	lastSeen   time.Time
}

func (p *Policy) drainMaxWait() time.Duration {
	if p.DrainMaxWait > 0 {
		return p.DrainMaxWait
	}
	return defaultDrainMaxWait
}

func (p *Policy) drainCooloff() time.Duration {
	if p.DrainCooloff > 0 {
		return p.DrainCooloff
	}
	return defaultDrainCooloff
}

// expireLocked drops unrefreshed drains and spent cool-offs. Caller holds exMu.
func (p *Policy) expireLocked(now time.Time) {
	for name, s := range p.exclusive {
		if !s.held && now.Sub(s.lastSeen) > drainTTL {
			p.logf("backends: the exclusive drain of %s for run=%s lapsed (not refreshed for %s)", name, s.runID, drainTTL)
			delete(p.exclusive, name)
		}
	}
	for run, until := range p.exCooloff {
		if !now.Before(until) {
			delete(p.exCooloff, run)
		}
	}
}

// exclusivelyBlocked reports whether name is operator-drained, or draining for or leased to a run
// other than runID ("": any run that does not own it).
func (p *Policy) exclusivelyBlocked(name, runID string) bool {
	p.exMu.Lock()
	defer p.exMu.Unlock()
	p.expireLocked(p.clock())
	if _, drained := p.adminDrains[name]; drained {
		return true
	}
	s, ok := p.exclusive[name]
	return ok && s.runID != runID
}

// ReserveExclusive implements Pool: (backend, true) only once that backend is empty and leased to
// runID. The lease counts as the run's claim, released by Release(backend, runID).
func (p *Policy) ReserveExclusive(ctx context.Context, affinity Affinity, runID string) (string, bool) {
	eligible := p.eligible(affinity)
	if len(eligible) == 0 || runID == "" || p.HoldsReservation(runID) {
		return "", false // a run that holds a claim already never drains or leases
	}
	order := p.selectOrder(ctx, eligible)

	p.exMu.Lock()
	now := p.clock()
	p.expireLocked(now)
	if p.exclusive == nil {
		p.exclusive = make(map[string]*exclusiveState)
	}
	if p.exCooloff == nil {
		p.exCooloff = make(map[string]time.Time)
	}
	var target string
	for name, s := range p.exclusive {
		if s.runID != runID {
			continue
		}
		if s.held {
			p.exMu.Unlock()
			return "", false // admitted already; never lease twice
		}
		target = name
		s.lastSeen = now
		if now.Sub(s.drainStart) > p.drainMaxWait() {
			delete(p.exclusive, name)
			p.exCooloff[runID] = now.Add(p.drainCooloff())
			p.exMu.Unlock()
			p.logf("backends: the exclusive drain of %s for run=%s gave up after %s (it never emptied); lifted for a %s cool-off", name, runID, p.drainMaxWait(), p.drainCooloff())
			return "", false
		}
		break
	}
	if target == "" {
		if until, cooling := p.exCooloff[runID]; cooling && now.Before(until) {
			p.exMu.Unlock()
			return "", false
		}
		for _, b := range order {
			_, taken := p.exclusive[b.Name]
			_, drained := p.adminDrains[b.Name]
			if !taken && !drained {
				target = b.Name
				break
			}
		}
		if target == "" {
			p.exMu.Unlock()
			return "", false // every eligible backend is draining or leased for another run
		}
		p.exclusive[target] = &exclusiveState{runID: runID, drainStart: now, lastSeen: now}
		p.logf("backends: exclusive run=%s draining %s (no new admissions to it until it is empty)", runID, target)
	}
	p.exMu.Unlock()

	// Probe outside the lock: it may be an HTTP read.
	var backend Backend
	for _, b := range eligible {
		if b.Name == target {
			backend = b
		}
	}
	if p.currentLoad(ctx, backend) > 0 {
		return "", false
	}

	p.exMu.Lock()
	defer p.exMu.Unlock()
	s, ok := p.exclusive[target]
	if !ok || s.runID != runID || s.held {
		return "", false // the drain lapsed or changed hands while probing; the next pass retries
	}
	if _, drained := p.adminDrains[target]; drained {
		return "", false // drained by the operator meanwhile
	}
	// The lease is the backend alone: its claim is refused while anything else is in flight there
	// (an attempt that took a slot since the backend was found empty).
	if held, full := p.claimReservation(runID, target, 1); held || full {
		return "", false
	}
	s.held = true
	p.logf("backends: exclusive run=%s leased %s (drained in %s)", runID, target, now.Sub(s.drainStart).Round(time.Second))
	return target, true
}

// releaseExclusive clears the lease on name only when runID holds it.
func (p *Policy) releaseExclusive(name, runID string) {
	if runID == "" {
		return
	}
	p.exMu.Lock()
	defer p.exMu.Unlock()
	if s, ok := p.exclusive[name]; ok && s.held && s.runID == runID {
		p.logf("backends: the exclusive lease of %s was released (run=%s)", name, runID)
		delete(p.exclusive, name)
	}
}

// filterForExclusive shapes Call's order: an exclusive run runs only on its leased backend; any
// other run skips the backends drained, or draining for or leased to someone else, except the one
// it reserved (a drain that began after its admission does not take its slot away).
func (p *Policy) filterForExclusive(order []Backend, affinity Affinity, reserved, runID string) []Backend {
	if affinity.Exclusive && reserved != "" {
		for _, b := range order {
			if b.Name == reserved {
				return []Backend{b}
			}
		}
	}
	out := make([]Backend, 0, len(order))
	for _, b := range order {
		if b.Name != reserved && p.exclusivelyBlocked(b.Name, runID) {
			continue
		}
		out = append(out, b)
	}
	return out
}
