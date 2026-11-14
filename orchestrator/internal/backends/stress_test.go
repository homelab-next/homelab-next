// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Many concurrent admit, release, die, late-release, stray-release, lease and reap interleavings,
// with two passes racing to reserve the same run id and token-weighted admission on. No count is
// ever negative, and once everything settles (a last reap with nothing live) every slot, token unit
// and lease is back.
func TestStress_AdmitReleaseReapSettles(t *testing.T) {
	e := newEngine(t, func() string { return kvBody("0.0") })
	p, _ := newPool(nil,
		Backend{Name: "shared", Weight: 1, LoadProbeURLs: []string{e.URL}},
		Backend{Name: "ex", Weight: 1, MaxContext: 1 << 20, MaxConcurrent: 6},
	)
	p.now = nil // the real clock: the reaper's grace and the caches move
	p.LoadMetrics, p.KV, p.TokenWeightedAdmission = testLoadMetrics, testKV, true
	p.AgentPromptP90 = func(string) (int, int) { return 114000, 20 } // weight 2
	p.DrainMaxWait = time.Hour
	normal := Affinity{ExcludeBackends: []string{"ex"}}
	normalEx := Affinity{MinContext: 1_000_000}
	excl := Affinity{MinContext: 1_000_000, Exclusive: true}
	ctx := context.Background()

	var liveMu sync.Mutex
	live := map[string]bool{}
	setLive := func(id string, on bool) {
		liveMu.Lock()
		defer liveMu.Unlock()
		if on {
			live[id] = true
		} else {
			delete(live, id)
		}
	}
	snapshot := func() map[string]bool {
		liveMu.Lock()
		defer liveMu.Unlock()
		m := make(map[string]bool, len(live))
		for k := range live {
			m[k] = true
		}
		return m
	}

	stop := make(chan struct{})
	var negative atomic.Int64
	var bg sync.WaitGroup
	bg.Add(2)
	go func() { // the reaper
		defer bg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			p.ReapStaleReservations(snapshot(), 0)
			time.Sleep(200 * time.Microsecond)
		}
	}()
	go func() { // a sampler
		defer bg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, b := range []string{"shared", "ex"} {
				if p.InFlight(b) < 0 {
					negative.Add(1)
				}
			}
			if p.TokenReservedUnits("shared") < -1e-6 {
				negative.Add(1)
			}
			time.Sleep(100 * time.Microsecond)
		}
	}()

	var wg sync.WaitGroup
	var admits, leases, deaths atomic.Int64
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(w)))
			for k := 0; k < 300; k++ {
				id := fmt.Sprintf("w%d-%d", w, k)
				setLive(id, true) // admitted before the reaper can see the claim
				var name string
				var ok bool
				switch rng.Intn(5) {
				case 4: // two overlapping passes reserve the same queued run
					var rw sync.WaitGroup
					names := make([]string, 2)
					for g := 0; g < 2; g++ {
						rw.Add(1)
						go func(g int) {
							defer rw.Done()
							if n, granted := p.Reserve(ctx, normal, id, "agent"); granted {
								names[g] = n
							}
						}(g)
					}
					rw.Wait()
					if names[0] != "" && names[1] != "" {
						// Both granted: legitimate only when the concurrent reaper (its live
						// snapshot can predate setLive) reaped the first claim in between.
						p.Release(names[1], id)
						names[1] = ""
					}
					for _, n := range names {
						if n != "" {
							name, ok = n, true
						}
					}
				case 0:
					for i := 0; i < 50 && !ok; i++ {
						if name, ok = p.ReserveExclusive(ctx, excl, id); !ok {
							time.Sleep(50 * time.Microsecond)
						}
					}
					if ok {
						leases.Add(1)
					}
				case 1:
					name, ok = p.Reserve(ctx, normalEx, id, "agent")
				default:
					name, ok = p.Reserve(ctx, normal, id, "agent")
				}
				if !ok {
					setLive(id, false)
					continue
				}
				admits.Add(1)
				time.Sleep(time.Duration(rng.Intn(200)) * time.Microsecond)
				switch r := rng.Intn(10); {
				case r == 0: // dies without releasing
					deaths.Add(1)
					setLive(id, false)
				case r == 1: // dies, then a late release after the reap
					deaths.Add(1)
					setLive(id, false)
					time.Sleep(time.Duration(rng.Intn(2000)) * time.Microsecond)
					p.Release(name, id)
				case r == 2: // a stray release from a run that never reserved
					p.Release(name, id+"-other")
					p.Release(name, id)
					setLive(id, false)
				default:
					p.Release(name, id)
					setLive(id, false)
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	bg.Wait()
	p.ReapStaleReservations(map[string]bool{}, 0)
	t.Logf("admits=%d leases=%d deaths=%d", admits.Load(), leases.Load(), deaths.Load())
	if admits.Load() == 0 || leases.Load() == 0 {
		t.Errorf("the mix did not exercise both paths: admits %d, leases %d", admits.Load(), leases.Load())
	}
	if n := negative.Load(); n != 0 {
		t.Errorf("a count was seen negative %d times", n)
	}
	for _, b := range []string{"shared", "ex"} {
		if n := p.InFlight(b); n != 0 {
			t.Errorf("in flight %s = %d after settling", b, n)
		}
	}
	if u := p.TokenReservedUnits("shared"); u > 1e-6 || u < -1e-6 {
		t.Errorf("token units = %v after settling", u)
	}
	p.exMu.Lock()
	defer p.exMu.Unlock()
	for name, s := range p.exclusive {
		if s.held {
			t.Errorf("the lease of %s is still held by %s after settling", name, s.runID)
		}
	}
}
