// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"context"
	"math"
	"strconv"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/scrape"
)

// Token-weighted admission. An engine's KV cache is one pool every running request shares, and
// request sizes span three orders of magnitude, yet the slot cap counts every job as one. This adds
// a second gate beside it:
//
//	admit while  sum(weights of this pool's live reservations) + w  <=  budget
//
// where w is the agent's p90 last-call prompt tokens over referenceSeqTokens, clamped to 0.5..4 (1
// with no history), and budget is KVBudgetFraction (0.8) of the engine's KV pool in the same unit.
// The pool's size is read from the engine's info metric (KV.Info, its PoolLabel, else BlocksLabel
// times BlockSizeLabel), summed over the backend's probe URLs; the engine's used fraction (KV.Usage)
// is a floor under the reservations, so traffic this pool did not send counts too.
//
// The slot cap is checked first and unchanged: the token budget only makes admission stricter.
// Everything here is behind TokenWeightedAdmission. A pool size that cannot be read (no probe URL,
// an unreachable endpoint, no info metric) skips the token gate for that backend: only the slot cap
// applies.

const (
	// referenceSeqTokens is the unit of a weight: the KV residency of one typical running
	// sequence, 57,000 tokens.
	referenceSeqTokens = 57000.0
	minAdmitWeight     = 0.5
	maxAdmitWeight     = 4.0
	// defaultKVBudgetFraction of the pool reservations may fill; the rest is headroom against
	// preemption and recompute.
	defaultKVBudgetFraction = 0.8

	engineSampleTTL = 5 * time.Second
	weightCacheTTL  = 60 * time.Second

	// maxRefusals bounds twRefusal: a cause a run never reads (it was cancelled while queued) is
	// only a label, so a full map is simply cleared.
	maxRefusals = 4096
)

type twReservation struct {
	backend string
	weight  float64
	at      time.Time
}

type engineSample struct {
	poolTokens float64 // 0: unknown
	usagePerc  float64 // 0..1
	fetched    time.Time
}

type weightSample struct {
	weight  float64
	fetched time.Time
}

// admitWeight is a reservation's weight from an agent's p90 last-call prompt size.
func admitWeight(p90, n int) float64 {
	if n <= 0 || p90 <= 0 {
		return 1.0
	}
	return math.Min(maxAdmitWeight, math.Max(minAdmitWeight, float64(p90)/referenceSeqTokens))
}

// weightFor is agentKey's weight, cached for weightCacheTTL so a deep queue does not ask for it
// once per job per pass.
func (p *Policy) weightFor(agentKey string) float64 {
	if !p.TokenWeightedAdmission || p.AgentPromptP90 == nil || agentKey == "" {
		return 1.0
	}
	now := p.clock()
	p.twMu.Lock()
	if c, ok := p.twWeights[agentKey]; ok && now.Sub(c.fetched) < weightCacheTTL {
		p.twMu.Unlock()
		return c.weight
	}
	p.twMu.Unlock()
	w := admitWeight(p.AgentPromptP90(agentKey))
	p.twMu.Lock()
	if p.twWeights == nil {
		p.twWeights = make(map[string]weightSample)
	}
	p.twWeights[agentKey] = weightSample{weight: w, fetched: now}
	p.twMu.Unlock()
	return w
}

func (p *Policy) kvBudgetFraction() float64 {
	if p.KVBudgetFraction > 0 && p.KVBudgetFraction <= 1 {
		return p.KVBudgetFraction
	}
	return defaultKVBudgetFraction
}

// engineReading is one probe URL's pool size and used fraction.
func (p *Policy) engineReading(samples []scrape.Sample) (pool, usage float64, ok bool) {
	label := func(s scrape.Sample, key string) (float64, bool) {
		if key == "" {
			return 0, false
		}
		v, err := strconv.ParseFloat(s.Labels[key], 64)
		return v, err == nil && v > 0 && !math.IsInf(v, 0)
	}
	for _, s := range samples {
		switch s.Name {
		case p.KV.Info:
			if v, good := label(s, p.KV.PoolLabel); good {
				pool, ok = v, true
				continue
			}
			if pool == 0 {
				nb, okb := label(s, p.KV.BlocksLabel)
				bs, oks := label(s, p.KV.BlockSizeLabel)
				if okb && oks {
					pool, ok = nb*bs, true
				}
			}
		case p.KV.Usage:
			if s.Value >= 0 && s.Value <= 1 {
				usage = math.Max(usage, s.Value)
			}
		}
	}
	return pool, usage, ok
}

// engineState is b's KV pool (summed over its probe URLs, each one engine) and used fraction,
// cached for engineSampleTTL. A failed read keeps the last pool size known.
func (p *Policy) engineState(ctx context.Context, b Backend) engineSample {
	if len(b.LoadProbeURLs) == 0 || p.KV.Info == "" {
		return engineSample{}
	}
	now := p.clock()
	p.twMu.Lock()
	prev, had := p.twEngines[b.Name]
	p.twMu.Unlock()
	if had && now.Sub(prev.fetched) < engineSampleTTL {
		return prev
	}
	want := scrape.Names(p.KV.Info, p.KV.Usage)
	var pool, used float64
	anyOK := false
	for _, u := range b.LoadProbeURLs {
		samples, err := scrape.Fetch(ctx, p.probeClient(), u, loadProbeTimeout, want)
		if err != nil {
			continue
		}
		po, us, ok := p.engineReading(samples)
		if !ok {
			continue
		}
		anyOK = true
		pool += po
		used += us * po
	}
	s := engineSample{fetched: now}
	switch {
	case anyOK && pool > 0:
		s.poolTokens, s.usagePerc = pool, used/pool
	case had:
		s.poolTokens = prev.poolTokens
	}
	p.twMu.Lock()
	if p.twEngines == nil {
		p.twEngines = make(map[string]engineSample)
	}
	p.twEngines[b.Name] = s
	p.twMu.Unlock()
	return s
}

// tokenBudgetAllows reports whether weight w fits b's budget; true when the feature is off or the
// pool's size is unknown.
func (p *Policy) tokenBudgetAllows(ctx context.Context, b Backend, w float64) bool {
	if !p.TokenWeightedAdmission {
		return true
	}
	s := p.engineState(ctx, b)
	if s.poolTokens <= 0 {
		return true
	}
	budget := p.kvBudgetFraction() * s.poolTokens / referenceSeqTokens
	p.twMu.Lock()
	reserved := p.twReserved[b.Name]
	p.twMu.Unlock()
	used := math.Max(reserved, s.usagePerc*s.poolTokens/referenceSeqTokens)
	return used+w <= budget+1e-9
}

// recordTokenReservation books w on backend for runID (feature on only).
func (p *Policy) recordTokenReservation(backend, runID string, w float64) {
	if !p.TokenWeightedAdmission || runID == "" {
		return
	}
	p.twMu.Lock()
	defer p.twMu.Unlock()
	if p.twReserved == nil {
		p.twReserved = make(map[string]float64)
		p.twByRun = make(map[string]twReservation)
	}
	if old, ok := p.twByRun[runID]; ok {
		p.twReserved[old.backend] -= old.weight
	}
	p.twByRun[runID] = twReservation{backend: backend, weight: w, at: p.clock()}
	p.twReserved[backend] += w
}

func (p *Policy) releaseTokenReservation(runID string) {
	if runID == "" {
		return
	}
	p.twMu.Lock()
	defer p.twMu.Unlock()
	p.releaseTokenReservationLocked(runID)
}

func (p *Policy) releaseTokenReservationLocked(runID string) bool {
	r, ok := p.twByRun[runID]
	if !ok {
		return false
	}
	delete(p.twByRun, runID)
	p.twReserved[r.backend] -= r.weight
	if p.twReserved[r.backend] < 1e-9 {
		p.twReserved[r.backend] = 0
	}
	return true
}

// reapOrphanTokenReservations returns the weight of every run that holds one but no claim (held),
// is not live and is older than grace: nothing else would ever release it.
func (p *Policy) reapOrphanTokenReservations(live, held map[string]bool, grace time.Duration, now time.Time) []string {
	p.twMu.Lock()
	defer p.twMu.Unlock()
	var out []string
	for id, r := range p.twByRun {
		if live[id] || held[id] || now.Sub(r.at) < grace {
			continue
		}
		if p.releaseTokenReservationLocked(id) {
			out = append(out, id)
		}
	}
	return out
}

// TokenReservedUnits is backend's reserved weight, in units of referenceSeqTokens.
func (p *Policy) TokenReservedUnits(backend string) float64 {
	p.twMu.Lock()
	defer p.twMu.Unlock()
	return p.twReserved[backend]
}

func (p *Policy) setRefusal(runID, cause string) {
	p.twMu.Lock()
	defer p.twMu.Unlock()
	if p.twRefusal == nil || len(p.twRefusal) >= maxRefusals {
		p.twRefusal = make(map[string]string)
	}
	p.twRefusal[runID] = cause
}

// LastRefusalCause implements Pool: it returns the cause once and forgets it.
func (p *Policy) LastRefusalCause(runID string) string {
	p.twMu.Lock()
	defer p.twMu.Unlock()
	c := p.twRefusal[runID]
	delete(p.twRefusal, runID)
	return c
}
