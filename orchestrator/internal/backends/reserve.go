// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"context"
	"sync/atomic"
	"time"
)

// Admission. A read-only "does anyone have room" check can be answered yes for several jobs in one
// scheduling pass, because a job's attempt counts itself only once its goroutine starts. Reserve
// closes that race: it picks a backend the way Call would and counts the slot before it returns, so
// the next Reserve in the same pass already sees it. The scheduler calls Reserve once per admission
// decision, from one goroutine, passes the backend to Call as reserved, and calls Release once that
// Call returns.
//
// A claim is recorded against its run id. A run id holds at most one claim: a second Reserve under
// it (an overlapping pass admitting the same queued run) is refused, because two claims would count
// two slots while the owner's release returns one, a leak the reaper cannot see. The reaper returns
// a claim whose run is no longer live; a late release of a reaped run returns nothing.

// Refusal causes (LastRefusalCause).
const (
	CauseSlot        = "slot"
	CauseTokenBudget = "token_budget"
)

// reapedRetention bounds Policy.reaped, which only tells a reaped run's late release apart from a
// stray one in the log; a release without a claim returns nothing either way.
const reapedRetention = time.Hour

type reservation struct {
	backend string
	at      time.Time
}

// Reserve implements Pool. runID "" is refused: a claim nobody owns could never be released.
func (p *Policy) Reserve(ctx context.Context, affinity Affinity, runID, agentKey string) (string, bool) {
	if runID == "" || p.HoldsReservation(runID) {
		return "", false
	}
	eligible := p.eligible(affinity)
	if len(eligible) == 0 {
		return "", false
	}
	w := p.weightFor(agentKey)
	cause := ""
	order, ratios := p.selectOrderRatios(ctx, eligible)
	for _, b := range order {
		if p.exclusivelyBlocked(b.Name, "") || !p.BackendUp(b.Name) {
			continue
		}
		ratio, read := ratios[b.Name]
		if !read {
			ratio = p.loadRatio(ctx, b) // PrimaryFirst or one backend: read only the ones reached
		}
		if b.MaxConcurrent > 0 && ratio >= 1.0 {
			if cause == "" {
				cause = CauseSlot
			}
			continue // the slot cap, checked first, whatever the token budget says
		}
		if !p.tokenBudgetAllows(ctx, b, w) {
			cause = CauseTokenBudget
			continue
		}
		held, full := p.claimReservation(runID, b.Name, b.MaxConcurrent)
		if held {
			return "", false // another pass claimed this run meanwhile
		}
		if full {
			cause = CauseSlot // another claim or attempt took the last slot since the ratio was read
			continue
		}
		p.recordTokenReservation(b.Name, runID, w)
		return b.Name, true
	}
	if cause != "" {
		p.setRefusal(runID, cause)
	}
	return "", false
}

// Release implements Pool: it returns runID's token weight, its slot and its lease. backend names
// where the caller believes the claim is; the claim's own backend is what is released.
func (p *Policy) Release(backend, runID string) {
	if runID == "" {
		return
	}
	p.releaseTokenReservation(runID)
	held, ok := p.dropReservation(runID)
	if !ok {
		return
	}
	if backend != "" && backend != held {
		p.logf("backends: release of run=%s named backend %s but its claim is on %s; releasing the claim", runID, backend, held)
	}
	atomic.AddInt64(p.inFlightCounter(held), -1)
	p.releaseExclusive(held, runID)
}

// claimReservation records runID's claim on backend and counts its slot together, under resMu, or
// refuses (nothing counted): held when runID holds one already, full when the backend is measured
// (max > 0) and its in-flight count is at max. The count is taken with the same compare-and-swap
// an attempt's slot is (takeSlot), so a reservation and a fallover attempt racing for the last
// slot cannot both have it. The reaper removes a claim under resMu before it returns the slot, so
// it never returns a slot that is not counted yet.
func (p *Policy) claimReservation(runID, backend string, max int) (held, full bool) {
	p.resMu.Lock()
	defer p.resMu.Unlock()
	if _, ok := p.reservations[runID]; ok {
		return true, false
	}
	if !p.takeSlot(Backend{Name: backend, MaxConcurrent: max}) {
		return false, true
	}
	if p.reservations == nil {
		p.reservations = make(map[string]reservation)
	}
	p.reservations[runID] = reservation{backend: backend, at: p.clock()}
	delete(p.reaped, runID) // a fresh claim supersedes an earlier reap of the same id
	return false, false
}

// HoldsReservation implements Pool.
func (p *Policy) HoldsReservation(runID string) bool {
	if runID == "" {
		return false
	}
	p.resMu.Lock()
	defer p.resMu.Unlock()
	_, held := p.reservations[runID]
	return held
}

// dropReservation forgets runID's claim and returns its backend; ok is false when runID holds none
// (the reaper returned it, or it never reserved), and then nothing may be released.
func (p *Policy) dropReservation(runID string) (string, bool) {
	p.resMu.Lock()
	defer p.resMu.Unlock()
	if r, held := p.reservations[runID]; held {
		delete(p.reservations, runID)
		return r.backend, true
	}
	if _, wasReaped := p.reaped[runID]; wasReaped {
		delete(p.reaped, runID)
		return "", false // its slot is back already
	}
	p.logf("backends: release of run=%s ignored: it holds no reservation", runID)
	return "", false
}

// ReapStaleReservations implements Pool: every claim whose run is not in live (the caller's
// admitted, running and awaiting runs) and is older than grace gives back its slot, its token
// weight and its exclusive lease. The pool's own count is the only load signal of a backend with no
// probe, so one leaked slot there would read as "full" for good. A token weight whose run holds no
// claim and is not live is returned too. It returns the reaped run ids.
func (p *Policy) ReapStaleReservations(live map[string]bool, grace time.Duration) []string {
	p.resMu.Lock()
	now := p.clock()
	var reaped, names []string
	for id, r := range p.reservations {
		if live[id] || now.Sub(r.at) < grace {
			continue
		}
		reaped = append(reaped, id)
		names = append(names, r.backend)
		delete(p.reservations, id)
		if p.reaped == nil {
			p.reaped = make(map[string]time.Time)
		}
		p.reaped[id] = now
	}
	for id, at := range p.reaped {
		if now.Sub(at) > reapedRetention {
			delete(p.reaped, id)
		}
	}
	held := make(map[string]bool, len(p.reservations))
	for id := range p.reservations {
		held[id] = true
	}
	p.resMu.Unlock()
	for i, id := range reaped {
		atomic.AddInt64(p.inFlightCounter(names[i]), -1)
		p.releaseTokenReservation(id)
		p.releaseExclusive(names[i], id)
		p.logf("backends: reaped run=%s on %s: it held a slot but is not in flight; slot returned", id, names[i])
	}
	for _, id := range p.reapOrphanTokenReservations(live, held, grace, now) {
		p.logf("backends: reaped run=%s: it held a token weight with no slot and is not in flight; weight returned", id)
	}
	return reaped
}
