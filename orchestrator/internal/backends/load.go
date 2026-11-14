// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"context"
	"math"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/scrape"
)

// Load is what a backend carries right now. Weighted round-robin balances the rate of first
// picks, which says nothing about occupancy: a backend whose jobs run long fills up at the same
// pick rate as one whose jobs end fast. So the pool measures it:
//
//   - a backend with load probes is read from its engines' own metrics (the LoadMetrics gauges,
//     its running and waiting requests, summed over every probe URL: one per engine, since a
//     balancer in front of several reports only one of them). That counts traffic this pool did
//     not send too;
//   - every backend also has the pool's own in-flight count (reservations, leases and running
//     attempts), exact for a backend nothing else calls.
//
// The load is the larger of the two, and the own count alone when every probe fails, so an
// unreadable backend never looks idle.

// defaultProbeTimeout bounds one metrics probe unless ProbeTimeout says otherwise.
const defaultProbeTimeout = 2 * time.Second

// sampleTTL is how long one probe's reading serves (at least the probe timeout, so a slow answer
// is not stale on arrival): one admission decision, or a burst of them, reads each URL once.
const sampleTTL = 1500 * time.Millisecond

// failBackoff is how long a failed probe (an error, a timeout, a status) is remembered before the
// URL is tried again, so an endpoint that never answers costs one timeout per backoff, not one per
// decision.
const failBackoff = 20 * time.Second

// probeEntry is one URL's last reading.
type probeEntry struct {
	mu      sync.Mutex // held while the URL is fetched, so concurrent readers wait for one fetch
	at      time.Time  // when the last fetch ended
	samples []scrape.Sample
	err     error
}

func (p *Policy) probeTimeout() time.Duration {
	if p.ProbeTimeout > 0 {
		return p.ProbeTimeout
	}
	return defaultProbeTimeout
}

// samples returns url's samples of every metric the pool reads (the load gauges and the KV pool's),
// fetched at most once per sampleTTL (or the probe timeout, if longer), and a failed fetch at most
// once per failBackoff.
func (p *Policy) samples(ctx context.Context, url string) ([]scrape.Sample, error) {
	p.probeMu.Lock()
	if p.probes == nil {
		p.probes = make(map[string]*probeEntry)
	}
	e := p.probes[url]
	if e == nil {
		e = &probeEntry{}
		p.probes[url] = e
	}
	p.probeMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.at.IsZero() {
		age, life := p.clock().Sub(e.at), max(sampleTTL, p.probeTimeout())
		if e.err != nil {
			life = max(failBackoff, p.probeTimeout())
		}
		if age >= 0 && age < life {
			return e.samples, e.err
		}
	}
	names := append(append([]string(nil), p.LoadMetrics...), p.KV.Info, p.KV.Usage)
	e.samples, e.err = scrape.Fetch(ctx, p.probeClient(), url, p.probeTimeout(), scrape.Names(names...))
	e.at = p.clock() // stamped when the fetch ended: a slow fetch is fresh, not already stale
	if e.err != nil && ctx.Err() != nil {
		e.at = time.Time{} // the caller's context ended it, not the endpoint: remember nothing
	}
	return e.samples, e.err
}

var (
	defaultProbeClientOnce sync.Once
	defaultProbeClient     *http.Client
)

func (p *Policy) probeClient() *http.Client {
	if p.ProbeClient != nil {
		return p.ProbeClient
	}
	defaultProbeClientOnce.Do(func() { defaultProbeClient = scrape.NewClient() })
	return defaultProbeClient
}

func (p *Policy) currentLoad(ctx context.Context, b Backend) int {
	tracked := int(atomic.LoadInt64(p.inFlightCounter(b.Name)))
	if len(b.LoadProbeURLs) == 0 || len(p.LoadMetrics) == 0 {
		return tracked
	}
	total, anyOK := 0.0, false
	for _, url := range b.LoadProbeURLs {
		samples, err := p.samples(ctx, url)
		if err != nil {
			continue
		}
		// A reading that is not a finite count of requests is no reading.
		if v, ok := scrape.Sum(samples, p.LoadMetrics...); ok && !math.IsInf(v, 0) && !math.IsNaN(v) && v >= 0 {
			total += v
			anyOK = true
		}
	}
	if !anyOK {
		return tracked
	}
	// Clamped before the conversion: a huge count reads as full, never as a wrapped integer.
	load := int(math.Min(total, maxLoadReading))
	if load < tracked {
		return tracked
	}
	return load
}

// maxLoadReading bounds a probe's load: past any real engine's queue, so a backend reporting more
// reads as full.
const maxLoadReading = 1 << 20

// loadRatio is the load as a fraction of MaxConcurrent; 0 for an unmeasured backend, which is
// never penalised for its load.
func (p *Policy) loadRatio(ctx context.Context, b Backend) float64 {
	if b.MaxConcurrent <= 0 {
		return 0
	}
	return float64(p.currentLoad(ctx, b)) / float64(b.MaxConcurrent)
}

// inFlightCounter is backend name's counter, created on first use.
func (p *Policy) inFlightCounter(name string) *int64 {
	p.inFlightMu.Lock()
	defer p.inFlightMu.Unlock()
	if p.inFlight == nil {
		p.inFlight = make(map[string]*int64)
	}
	c, ok := p.inFlight[name]
	if !ok {
		c = new(int64)
		p.inFlight[name] = c
	}
	return c
}

// takeSlot counts one more attempt on b unless b is measured (MaxConcurrent > 0) and already at it;
// it reports whether it counted one. giveSlot returns it.
func (p *Policy) takeSlot(b Backend) bool {
	c := p.inFlightCounter(b.Name)
	for {
		v := atomic.LoadInt64(c)
		if b.MaxConcurrent > 0 && v >= int64(b.MaxConcurrent) {
			return false
		}
		if atomic.CompareAndSwapInt64(c, v, v+1) {
			return true
		}
	}
}

func (p *Policy) giveSlot(b Backend) { atomic.AddInt64(p.inFlightCounter(b.Name), -1) }

// InFlight is the pool's own in-flight count on backend name (reservations, leases and running
// attempts).
func (p *Policy) InFlight(name string) int64 { return atomic.LoadInt64(p.inFlightCounter(name)) }

// InFlightSnapshot is each backend's in-flight count and the run ids holding a claim on it.
func (p *Policy) InFlightSnapshot() map[string]InFlightStatus {
	out := map[string]InFlightStatus{}
	p.inFlightMu.Lock()
	for name, c := range p.inFlight {
		out[name] = InFlightStatus{InFlight: atomic.LoadInt64(c), ReservedRuns: []string{}}
	}
	p.inFlightMu.Unlock()
	p.resMu.Lock()
	for id, r := range p.reservations {
		e, ok := out[r.backend]
		if !ok {
			e = InFlightStatus{ReservedRuns: []string{}}
		}
		e.ReservedRuns = append(e.ReservedRuns, id)
		out[r.backend] = e
	}
	p.resMu.Unlock()
	for name, e := range out {
		sort.Strings(e.ReservedRuns)
		out[name] = e
	}
	return out
}

// InFlightStatus is one backend's entry of InFlightSnapshot.
type InFlightStatus struct {
	InFlight     int64    `json:"in_flight"`
	ReservedRuns []string `json:"reserved_runs"`
}
