// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// A drained backend takes no new reservation (others still do); a run already on it keeps it; the
// drain never lapses on its own; undrain restores admission.
func TestDrain_BlocksNewWorkKeepsRunningWorkAndUndrains(t *testing.T) {
	ctx := context.Background()
	p, clk := newPool(nil, Backend{Name: "main", MaxConcurrent: 8}, Backend{Name: "spare", MaxConcurrent: 8})
	pin := Affinity{ExcludeBackends: []string{"spare"}}
	running, ok := p.Reserve(ctx, pin, "run-a", "")
	if !ok || running != "main" {
		t.Fatalf("reserve = %q, %v", running, ok)
	}
	st, err := p.SetDrained("main", true)
	if err != nil || !st.Drained || st.InFlight != 1 || st.Since.IsZero() {
		t.Fatalf("drain = %+v, %v", st, err)
	}
	if b, ok := p.Reserve(ctx, pin, "run-x", ""); ok {
		t.Fatalf("admitted to a drained backend: %q", b)
	}
	if b, ok := p.Reserve(ctx, Affinity{}, "run-b", ""); !ok || b != "spare" {
		t.Fatalf("an undrained backend did not admit: %q, %v", b, ok)
	}
	order := []Backend{{Name: "main"}, {Name: "spare"}}
	if got := p.filterForExclusive(order, Affinity{}, "main", "run-a"); len(got) != 2 {
		t.Errorf("the run reserved on main lost it: %v", got)
	}
	if got := p.filterForExclusive(order, Affinity{}, "spare", "run-b"); len(got) != 1 || got[0].Name != "spare" {
		t.Errorf("another run's failover landed on the drained backend: %v", got)
	}
	clk.add(6 * time.Hour)
	if !p.Drained("main") {
		t.Fatal("the drain lapsed on its own")
	}
	if again, _ := p.SetDrained("main", true); !again.Since.Equal(st.Since) {
		t.Errorf("draining again moved since: %v -> %v", st.Since, again.Since)
	}
	p.Release(running, "run-a")
	if st, _ := p.SetDrained("main", false); st.Drained || !st.Since.IsZero() {
		t.Errorf("undrain = %+v", st)
	}
	if b, ok := p.Reserve(ctx, pin, "run-c", ""); !ok || b != "main" {
		t.Fatalf("the undrained backend did not admit: %q, %v", b, ok)
	}
}

// An exclusive job neither picks a drained backend nor turns an earlier drain into a lease while
// the operator's drain holds.
func TestDrain_AnExclusiveRunNeverLeasesADrainedBackend(t *testing.T) {
	ctx := context.Background()
	p, _ := newPool(nil, Backend{Name: "big", MaxContext: 1 << 20, MaxConcurrent: 8})
	if _, err := p.SetDrained("big", true); err != nil {
		t.Fatal(err)
	}
	if b, ok := p.ReserveExclusive(ctx, exclusiveBig, "run-big"); ok {
		t.Fatalf("leased a drained backend: %q", b)
	}
	_, _ = p.SetDrained("big", false)
	if b, ok := p.ReserveExclusive(ctx, exclusiveBig, "run-big"); !ok || b != "big" {
		t.Fatalf("after undrain = %q, %v", b, ok)
	}

	q, _ := newPool(nil, Backend{Name: "big", MaxContext: 1 << 20, MaxConcurrent: 8})
	if _, ok := q.Reserve(ctx, Affinity{}, "busy", ""); !ok {
		t.Fatal("reserve")
	}
	q.ReserveExclusive(ctx, exclusiveBig, "run-big") // starts draining
	_, _ = q.SetDrained("big", true)
	q.Release("big", "busy") // empty now
	if b, ok := q.ReserveExclusive(ctx, exclusiveBig, "run-big"); ok {
		t.Fatalf("leased an operator-drained backend: %q", b)
	}
}

func TestDrain_AnUnknownBackendAndTheSnapshot(t *testing.T) {
	p, _ := newPool(nil, Backend{Name: "a"}, Backend{Name: "b"})
	if _, err := p.SetDrained("nope", true); !errors.Is(err, ErrUnknownBackend) {
		t.Errorf("unknown backend: %v", err)
	}
	_, _ = p.SetDrained("b", true)
	for _, h := range p.HealthSnapshot() {
		if h.Drained != (h.Backend == "b") {
			t.Errorf("%s drained = %v", h.Backend, h.Drained)
		}
	}
}

type memDrainStore struct {
	mu   sync.Mutex
	m    map[string]time.Time
	fail bool
}

func (s *memDrainStore) SaveDrain(n string, since time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("disk full")
	}
	if _, ok := s.m[n]; !ok {
		s.m[n] = since
	}
	return nil
}

func (s *memDrainStore) DeleteDrain(n string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("disk full")
	}
	delete(s.m, n)
	return nil
}

func (s *memDrainStore) LoadDrains() (map[string]time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]time.Time{}
	for k, v := range s.m {
		out[k] = v
	}
	return out, nil
}

// An operator drain survives a restart with its since; a stored drain of a backend no longer
// configured is dropped; a drain that cannot be stored is refused and changes nothing.
func TestDrain_PersistsAcrossARestart(t *testing.T) {
	st := &memDrainStore{m: map[string]time.Time{}}
	p, _ := newPool(nil, Backend{Name: "a"}, Backend{Name: "b"})
	p.DrainStore = st
	first, err := p.SetDrained("a", true)
	if err != nil {
		t.Fatal(err)
	}
	st.m["retired"] = first.Since

	restarted, _ := newPool(nil, Backend{Name: "a"}, Backend{Name: "b"})
	restarted.DrainStore = st
	if err := restarted.RestoreDrains(); err != nil {
		t.Fatal(err)
	}
	if !restarted.Drained("a") || restarted.Drained("b") {
		t.Fatalf("after restart a=%v b=%v", restarted.Drained("a"), restarted.Drained("b"))
	}
	if again, _ := restarted.SetDrained("a", true); !again.Since.Equal(first.Since) {
		t.Errorf("the restored drain lost its since: %v -> %v", first.Since, again.Since)
	}
	if _, stale := st.m["retired"]; stale {
		t.Error("the stored drain of an unconfigured backend was kept")
	}
	if _, err := restarted.SetDrained("a", false); err != nil || len(st.m) != 0 {
		t.Errorf("the undrain was not stored: %v %v", err, st.m)
	}
	st.fail = true
	if _, err := restarted.SetDrained("b", true); err == nil || restarted.Drained("b") {
		t.Errorf("an unstorable drain: err %v, drained %v", err, restarted.Drained("b"))
	}
	if err := (&Policy{Log: quiet}).RestoreDrains(); err != nil {
		t.Errorf("no store: %v", err)
	}
}
