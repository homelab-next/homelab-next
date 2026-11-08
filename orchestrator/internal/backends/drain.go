// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"errors"
	"fmt"
	"time"
)

// Operator drains. A drained backend takes no new admission and no other run's failover, through
// the same gate an exclusive drain uses (exclusivelyBlocked), while runs already admitted to it
// finish. Unlike an exclusive drain it has no expiry, lease or owner: it holds until undrained,
// for maintenance and model swaps. A job whose eligible backends are all drained stays queued.
//
// With a DrainStore every change is written through before it takes effect, and RestoreDrains
// re-applies the stored drains at start, so a restart in the middle of a model swap does not
// undrain a backend. A stored drain for a backend no longer configured is dropped (logged).

// DrainStore persists operator drains (the store implements it).
type DrainStore interface {
	SaveDrain(backend string, since time.Time) error
	DeleteDrain(backend string) error
	LoadDrains() (map[string]time.Time, error)
}

// ErrUnknownBackend: no configured local backend has that name.
var ErrUnknownBackend = errors.New("no configured local backend has that name")

// DrainStatus is one backend's operator-drain state.
type DrainStatus struct {
	Backend  string    `json:"backend"`
	Drained  bool      `json:"drained"`
	Since    time.Time `json:"since,omitempty"`
	InFlight int64     `json:"in_flight"`
}

func (p *Policy) knownBackend(name string) bool {
	for _, b := range p.Backends {
		if b.Name == name {
			return true
		}
	}
	return false
}

// RestoreDrains re-applies the stored drains; call it once at start, before scheduling. A load
// error is returned for the caller to decide on.
func (p *Policy) RestoreDrains() error {
	if p.DrainStore == nil {
		p.logf("backends: operator drains are not persisted (no drain store); none restored")
		return nil
	}
	saved, err := p.DrainStore.LoadDrains()
	if err != nil {
		return err
	}
	var stale []string
	p.exMu.Lock()
	if p.adminDrains == nil {
		p.adminDrains = make(map[string]time.Time)
	}
	for name, since := range saved {
		if !p.knownBackend(name) {
			stale = append(stale, name)
			continue
		}
		p.adminDrains[name] = since
		p.logf("backends: %s is still drained by the operator (since %s, restored after a restart); undrain it to resume admissions", name, since.Format(time.RFC3339))
	}
	p.exMu.Unlock()
	for _, name := range stale {
		p.logf("backends: dropping the stored drain of %s: no configured backend has that name", name)
		if err := p.DrainStore.DeleteDrain(name); err != nil {
			p.logf("backends: could not drop the stored drain of %s: %v", name, err)
		}
	}
	return nil
}

// SetDrained drains (on) or undrains backend name and returns its new state. Draining a drained
// backend keeps its first since. When the store refuses the change, nothing changes.
func (p *Policy) SetDrained(name string, on bool) (DrainStatus, error) {
	if !p.knownBackend(name) {
		return DrainStatus{}, ErrUnknownBackend
	}
	p.exMu.Lock()
	if p.adminDrains == nil {
		p.adminDrains = make(map[string]time.Time)
	}
	since, was := p.adminDrains[name]
	now := p.clock().UTC()
	if p.DrainStore != nil && on != was {
		var perr error
		if on {
			perr = p.DrainStore.SaveDrain(name, now)
		} else {
			perr = p.DrainStore.DeleteDrain(name)
		}
		if perr != nil {
			p.exMu.Unlock()
			return DrainStatus{}, fmt.Errorf("persist the drain state of %s: %w", name, perr)
		}
	}
	switch {
	case on && !was:
		since = now
		p.adminDrains[name] = since
		p.logf("backends: %s drained by the operator (no new admissions or failover; running attempts continue)", name)
	case !on && was:
		delete(p.adminDrains, name)
		since = time.Time{}
		p.logf("backends: %s undrained by the operator", name)
	case !on:
		since = time.Time{}
	}
	p.exMu.Unlock()
	return DrainStatus{Backend: name, Drained: on, Since: since, InFlight: p.InFlight(name)}, nil
}

// Drained implements Pool.
func (p *Policy) Drained(name string) bool {
	p.exMu.Lock()
	defer p.exMu.Unlock()
	_, ok := p.adminDrains[name]
	return ok
}
