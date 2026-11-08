// SPDX-License-Identifier: Apache-2.0

// Package backends is the controller's backend pool and attempt chain: which local backend a job
// is admitted to (reservations, the slot cap, token-weighted admission, health, operator drains,
// exclusive leases), and the order one job's attempts run in (each eligible local backend, then
// the cloud leg).
//
// Every attempt is a runner.Session handed to a runner.Runner. What happens after a failure is
// decided from the runner's classes (runner.ClassOf, applied to one attempt's error at a time),
// the runner's absent-backend hint (runner.LooksAbsent, which only prompts a probe), its answer
// check (runner.AnswerChecker) and the pool's own sentinel errors; never from an error's text,
// which can quote the model's own output. TestTheCoreReadsNoErrorText holds that.
//
// The pool sends no request to a model. Its only HTTP traffic is GET probes: a backend's
// health_url and its load_probe_urls (package scrape).
package backends

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/inference"
	"github.com/homelab-next/homelab-next/orchestrator/internal/profile"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
)

// Pool is what the queue admits and runs jobs through. *Policy implements it; a test of the queue
// can stub it.
type Pool interface {
	// Reserve admits runID to a backend with room for affinity, counting its slot (and, with
	// token-weighted admission, its weight) at once; ("", false) leaves the job queued. A run id
	// holds at most one claim.
	Reserve(ctx context.Context, affinity Affinity, runID, agentKey string) (backend string, ok bool)
	// ReserveExclusive is Reserve for an exclusive profile: it drains a backend for runID and
	// leases it once it is empty. Call it once per scheduling pass while the job is queued.
	ReserveExclusive(ctx context.Context, affinity Affinity, runID string) (backend string, ok bool)
	// Release returns runID's claim (slot, weight, lease); a run with none releases nothing.
	Release(backend, runID string)
	// HoldsReservation reports whether runID holds a claim.
	HoldsReservation(runID string) bool
	// LastRefusalCause returns, once, why runID's last Reserve refused: CauseSlot, CauseTokenBudget
	// or "".
	LastRefusalCause(runID string) string
	// AnyHealthy reports whether a backend eligible for affinity is up (true when none is
	// eligible: that is a capacity mismatch, not an outage).
	AnyHealthy(affinity Affinity) bool
	// Drained reports whether the operator drained backend.
	Drained(backend string) bool
	// ExplainEligibility says whether backend satisfies affinity and, when not, why.
	ExplainEligibility(backend string, affinity Affinity) (found, ok bool, reason string)
	// ReapStaleReservations returns the claims of runs not in live and older than grace.
	ReapStaleReservations(live map[string]bool, grace time.Duration) []string
	// Call runs one job's attempt chain.
	Call(ctx context.Context, s runner.Session, locality Locality, affinity Affinity, reserved string) (*Result, error)
	// JobTimeout bounds one job's whole attempt chain; 0 is none. A caller that runs Call more
	// than once for a job (its profile's max_attempts) puts this deadline on its own context
	// once, before the first, so a retry gets no fresh budget.
	JobTimeout() time.Duration
}

var _ Pool = (*Policy)(nil)

// Backend is one local backend: a runner home whose own configuration points its sessions at one
// model server, with what the pool knows of its capacity and how to probe it.
type Backend struct {
	Name string
	// Home is the runner's configuration reference for sessions here (backends.*.home); opaque.
	Home string
	// NeedsInterlock: an attempt here holds the shared interlock for its whole session, for a
	// backend that serves one call at a time across every program that calls it.
	NeedsInterlock bool
	// Weight is the backend's share of first picks in weighted round-robin; 0 or less counts as
	// 1, never as none.
	Weight int
	// Tags and MaxContext are declared, never checked against the model the backend serves.
	// MaxContext 0 is unknown, which no min_context accepts.
	Tags       []string
	MaxContext int
	// MaxConcurrent is the backend's measured concurrent-request ceiling; 0 is unmeasured, which
	// is never treated as full.
	MaxConcurrent int
	// LoadProbeURLs are metrics endpoints (one per engine, summed) read for the backend's load and
	// its KV pool; empty: the pool's own in-flight count. Probes only.
	LoadProbeURLs []string
	// HealthURL is GET-probed; empty: never marked down. A probe only.
	HealthURL string
	// Endpoint is host:port of the model server, which a runner's progress liveness watches for
	// socket traffic. A probe only; never set on the cloud leg.
	Endpoint string
}

func (b Backend) weight() int {
	if b.Weight <= 0 {
		return 1
	}
	return b.Weight
}

func (b Backend) hasAllTags(required []string) bool {
	for _, want := range required {
		if !slices.Contains(b.Tags, want) {
			return false
		}
	}
	return true
}

// Affinity constrains which local backends a profile's calls may land on. The zero value imposes
// no constraint.
type Affinity struct {
	// RequireTags: a backend must carry every one.
	RequireTags []string
	// ExcludeBackends: a backend named here is never eligible, checked first.
	ExcludeBackends []string
	// MinContext: a backend must declare at least this window; one that declares none fails.
	MinContext int
	// Exclusive: the run has its backend alone (exclusive.go). Not an eligibility constraint.
	Exclusive bool
}

// AffinityOf is a profile's backend_affinity.
func AffinityOf(a profile.BackendAffinity) Affinity {
	return Affinity{
		RequireTags:     slices.Clone(a.RequireTags),
		ExcludeBackends: slices.Clone(a.ExcludeBackends),
		MinContext:      a.MinContext,
		Exclusive:       a.Exclusive,
	}
}

// IsZero reports whether a narrows nothing (Exclusive is not a narrowing).
func (a Affinity) IsZero() bool {
	return len(a.RequireTags) == 0 && len(a.ExcludeBackends) == 0 && a.MinContext == 0
}

// satisfies is the one per-backend eligibility check: by name, then tags, then context.
func satisfies(b Backend, a Affinity) (ok bool, reason string) {
	if slices.Contains(a.ExcludeBackends, b.Name) {
		return false, "excluded by name (exclude_backends)"
	}
	if !b.hasAllTags(a.RequireTags) {
		return false, fmt.Sprintf("missing required tag(s): backend has %v, profile requires %v", b.Tags, a.RequireTags)
	}
	if a.MinContext > 0 && b.MaxContext < a.MinContext {
		return false, fmt.Sprintf("backend's declared max_context (%d) is below the profile's min_context (%d)", b.MaxContext, a.MinContext)
	}
	return true, ""
}

// KVMetrics names the metrics a backend's load probes give its KV pool by, for token-weighted
// admission. Nothing has a default: an engine names its own.
type KVMetrics struct {
	// Info is an info metric whose labels give the pool's size.
	Info string
	// PoolLabel is Info's label holding the pool in tokens; BlocksLabel times BlockSizeLabel is
	// read when it is missing.
	PoolLabel      string
	BlocksLabel    string
	BlockSizeLabel string
	// Usage is a gauge of the pool's used fraction (0 to 1), which counts the engine's traffic
	// from other callers too; empty: only this pool's own reservations count.
	Usage string
}

// Policy is the pool. The zero value of every setting keeps a feature off; its exported fields are
// set once, before first use, and never changed after.
type Policy struct {
	// Runner runs every attempt (local and cloud). Required.
	Runner runner.Runner
	// Backends are the local backends, in configured order (the order PrimaryFirst keeps and a
	// fallback chain tries after the first pick).
	Backends []Backend
	// CloudHome is the cloud leg's runner home; empty: there is no cloud leg, and a job whose
	// local attempts all fail fails.
	CloudHome string
	// Interlock is the shared lock a NeedsInterlock backend's attempts hold; nil disables it.
	// InterlockWait bounds the wait for it: past it the attempt is a runner.BackendFault (busy),
	// and the chain moves on. 0 waits for as long as the job may.
	Interlock     *inference.Interlock
	InterlockWait time.Duration
	// Limits are every attempt's runner limits (local and cloud).
	Limits runner.Limits
	// JobLimit bounds one Call's whole chain; 0 is none (JobTimeout).
	JobLimit time.Duration
	// PrimaryFirst keeps the configured order for first picks instead of weighted round-robin and
	// skips load ranking; the slot cap still moves a job past a full backend.
	PrimaryFirst bool

	// ProbeClient is the client of every probe; nil is scrape.NewClient() (no proxy, no redirect).
	// ProbeTimeout bounds one metrics probe; 0 is 2 seconds.
	ProbeClient  *http.Client
	ProbeTimeout time.Duration
	// LoadMetrics are the gauges a load probe sums into a backend's load (its running and waiting
	// requests). Required when a backend has LoadProbeURLs (Validate).
	LoadMetrics []string
	// KV names the KV pool's metrics, required with TokenWeightedAdmission.
	KV KVMetrics
	// TokenWeightedAdmission admits against a KV-token budget beside the slot cap (tokens.go).
	// Off: nothing of it runs. KVBudgetFraction 0 is 0.8. AgentPromptP90 gives an agent's p90
	// last-call prompt tokens and the sample count behind it (n == 0: no history, weight 1).
	TokenWeightedAdmission bool
	KVBudgetFraction       float64
	AgentPromptP90         func(agentKey string) (p90, n int)

	// DrainStore persists operator drains across restarts; nil keeps them in memory only.
	DrainStore DrainStore
	// DrainMaxWait and DrainCooloff bound an exclusive drain (exclusive.go); 0 is 30 minutes each.
	DrainMaxWait time.Duration
	DrainCooloff time.Duration

	// ConcurrencyWait is the pause before an attempt classed runner.ConcurrencyLimited (the
	// gateway's 429 concurrency_limited) is asked again on the same backend; 0 is one second, the
	// gateway's Retry-After. ConcurrencyWaits bounds those pauses in one leg; 0 is
	// DefaultConcurrencyWaits. Past it the chain ends with ErrConcurrencyLimited: it never falls
	// over to another backend or to the cloud for a limit, and never marks the backend down.
	// CloudConcurrencyWaits is the cloud leg's bound (0 is DefaultCloudConcurrencyWaits).
	ConcurrencyWait       time.Duration
	ConcurrencyWaits      int
	CloudConcurrencyWaits int

	// Log receives the pool's log lines; nil is log.Printf.
	Log func(format string, args ...any)

	now   func() time.Time                                // test seam for every clock the pool reads
	sleep func(ctx context.Context, d time.Duration) bool // test seam for the concurrency wait

	probeMu sync.Mutex
	probes  map[string]*probeEntry // load probe URL -> its last reading

	inFlightMu sync.Mutex
	inFlight   map[string]*int64

	resMu        sync.Mutex
	reservations map[string]reservation
	reaped       map[string]time.Time

	exMu        sync.Mutex
	exclusive   map[string]*exclusiveState
	exCooloff   map[string]time.Time
	adminDrains map[string]time.Time

	twMu       sync.Mutex
	twReserved map[string]float64
	twByRun    map[string]twReservation
	twEngines  map[string]engineSample
	twWeights  map[string]weightSample
	twRefusal  map[string]string

	health healthTable

	rrMu sync.Mutex
	// rrCurrent is each backend's smooth weighted round-robin total, keyed by name: calls see
	// different eligible subsets, and a backend outside one keeps its total for the next.
	rrCurrent map[string]int
}

// ErrInvalid is wrapped by Validate.
var ErrInvalid = errors.New("backends: invalid pool")

// Validate checks the settings a pool cannot run correctly without. The controller calls it once
// at start; a pool that fails it must not be used, because each problem it reports would make a
// feature read nothing and keep quiet about it.
func (p *Policy) Validate() error {
	if p.Runner == nil {
		return fmt.Errorf("%w: no runner", ErrInvalid)
	}
	seen := map[string]bool{}
	for _, b := range p.Backends {
		switch {
		case b.Name == "":
			return fmt.Errorf("%w: a backend has no name", ErrInvalid)
		case seen[b.Name]:
			return fmt.Errorf("%w: two backends are named %q", ErrInvalid, b.Name)
		case len(b.LoadProbeURLs) > 0 && len(p.LoadMetrics) == 0:
			return fmt.Errorf("%w: backend %q has load probes but no load metric is named, so they would read nothing", ErrInvalid, b.Name)
		case b.Weight < 0 || b.Weight > maxWeight:
			return fmt.Errorf("%w: backend %q: weight %d is outside 0..%d", ErrInvalid, b.Name, b.Weight, maxWeight)
		}
		urls := append([]string(nil), b.LoadProbeURLs...)
		if b.HealthURL != "" {
			urls = append(urls, b.HealthURL)
		}
		for _, u := range urls {
			if err := checkProbeURL(u); err != nil {
				return fmt.Errorf("%w: backend %q: %w", ErrInvalid, b.Name, err)
			}
		}
		seen[b.Name] = true
	}
	if p.TokenWeightedAdmission && (p.KV.Info == "" || (p.KV.PoolLabel == "" && (p.KV.BlocksLabel == "" || p.KV.BlockSizeLabel == ""))) {
		return fmt.Errorf("%w: token-weighted admission needs the KV pool's info metric and its size label(s)", ErrInvalid)
	}
	if p.KVBudgetFraction < 0 || p.KVBudgetFraction > 1 {
		return fmt.Errorf("%w: kv budget fraction %v is outside 0..1", ErrInvalid, p.KVBudgetFraction)
	}
	switch p.Limits.Liveness {
	case "", "cpu", "progress":
	default:
		return fmt.Errorf("%w: liveness %q: want cpu or progress", ErrInvalid, p.Limits.Liveness)
	}
	return nil
}

// maxWeight bounds a backend's weight: the round-robin's totals add weights on every pick.
const maxWeight = 1000

// checkProbeURL accepts an http or https URL with a host and no userinfo (a probe carries no
// credential, and an error quoting the URL must not quote one). The URL is never quoted back.
func checkProbeURL(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return errors.New("a probe URL does not parse")
	case u.Scheme != "http" && u.Scheme != "https":
		return errors.New("a probe URL is not http or https")
	case u.Hostname() == "":
		return errors.New("a probe URL has no host")
	case u.User != nil:
		return errors.New("a probe URL carries userinfo")
	}
	return nil
}

// JobTimeout implements Pool.
func (p *Policy) JobTimeout() time.Duration { return p.JobLimit }

func (p *Policy) logf(format string, args ...any) {
	if p.Log != nil {
		p.Log(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (p *Policy) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// eligible is p.Backends narrowed to affinity, in configured order. A zero affinity returns
// p.Backends itself: callers that reorder must copy.
func (p *Policy) eligible(affinity Affinity) []Backend {
	if affinity.IsZero() {
		return p.Backends
	}
	out := make([]Backend, 0, len(p.Backends))
	for _, b := range p.Backends {
		if ok, _ := satisfies(b, affinity); ok {
			out = append(out, b)
		}
	}
	return out
}

// ExplainEligibility implements Pool: found is false when no backend has that name.
func (p *Policy) ExplainEligibility(backend string, affinity Affinity) (found, ok bool, reason string) {
	for _, b := range p.Backends {
		if b.Name == backend {
			ok, reason := satisfies(b, affinity)
			return true, ok, reason
		}
	}
	return false, false, ""
}

// pickOrder puts first the backend smooth weighted round-robin finds most due, the rest after it
// in their order. Each backend's total grows by its weight per call, the highest total is picked
// and lowered by the sum of this call's weights; ties go to the earlier backend.
func (p *Policy) pickOrder(backends []Backend) []Backend {
	if len(backends) <= 1 {
		return backends
	}
	p.rrMu.Lock()
	defer p.rrMu.Unlock()
	if p.rrCurrent == nil {
		p.rrCurrent = make(map[string]int, len(backends))
	}
	total, best := 0, 0
	for i, b := range backends {
		p.rrCurrent[b.Name] += b.weight()
		total += b.weight()
		if p.rrCurrent[b.Name] > p.rrCurrent[backends[best].Name] {
			best = i
		}
	}
	p.rrCurrent[backends[best].Name] -= total
	order := make([]Backend, 0, len(backends))
	order = append(order, backends[best])
	for i, b := range backends {
		if i != best {
			order = append(order, b)
		}
	}
	return order
}

// selectOrder is the attempt order for a fresh pick: pickOrder's, then stable-sorted by load ratio
// (least loaded first), so backends tied on load (unmeasured ones are all 0) keep the round-robin's
// order. PrimaryFirst keeps the configured order. Always a copy. The ratios are read concurrently,
// one probe per URL at most; selectOrderRatios returns them too (nil with PrimaryFirst or one
// backend).
func (p *Policy) selectOrder(ctx context.Context, backends []Backend) []Backend {
	order, _ := p.selectOrderRatios(ctx, backends)
	return order
}

// selectOrderRatios is selectOrder with the ratios it read.
func (p *Policy) selectOrderRatios(ctx context.Context, backends []Backend) ([]Backend, map[string]float64) {
	if p.PrimaryFirst {
		return slices.Clone(backends), nil
	}
	order := slices.Clone(p.pickOrder(backends))
	if len(order) <= 1 {
		return order, nil
	}
	ratios := p.loadRatios(ctx, order)
	sort.SliceStable(order, func(i, j int) bool { return ratios[order[i].Name] < ratios[order[j].Name] })
	return order, ratios
}

// loadRatios reads every backend's load ratio concurrently.
func (p *Policy) loadRatios(ctx context.Context, backends []Backend) map[string]float64 {
	ratios := make(map[string]float64, len(backends))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, b := range backends {
		wg.Add(1)
		go func(b Backend) {
			defer wg.Done()
			r := p.loadRatio(ctx, b)
			mu.Lock()
			ratios[b.Name] = r
			mu.Unlock()
		}(b)
	}
	wg.Wait()
	return ratios
}

// moveToFront returns a copy of order with the backend named name first, the rest in order.
func moveToFront(order []Backend, name string) []Backend {
	out := make([]Backend, 0, len(order))
	for _, b := range order {
		if b.Name == name {
			out = append(out, b)
		}
	}
	for _, b := range order {
		if b.Name != name {
			out = append(out, b)
		}
	}
	return out
}
