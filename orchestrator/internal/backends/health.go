// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
)

// Health. The pool is the one place that knows whether a local backend is up, and every routing
// path reads it: a backend marked down is skipped at once (no session spent rediscovering the
// outage), Reserve does not admit to it, and a local-only job with no healthy eligible backend
// fails with ErrNoHealthyBackend, which the scheduler requeues rather than fails.
//
// Only the pool's own GET of a backend's health_url decides:
//   - the prober (RunHealthProber) marks a backend down after downAfterProbeFailures failed probes
//     in a row and up after one good one;
//   - an attempt whose failure carries the runner's absent hint (runner.LooksAbsent) triggers one
//     probe at once (confirmBackendDown), and only a failed probe marks the backend down. The hint
//     alone never does, nor does any class: a failure's text can quote the model's own output,
//     and a runner.BackendFault is one attempt's view, not an outage.
//
// A backend with no health_url is never marked down, since nothing could bring it back up.

const downAfterProbeFailures = 2

// healthProbeTimeout bounds one health probe.
const healthProbeTimeout = 5 * time.Second

var (
	// ErrNoHealthyBackend: every eligible local backend is marked down, so no attempt ran. The
	// cloud gate counts it as the backend's; a local-only job failing with it waits queued.
	ErrNoHealthyBackend = errors.New("no healthy local backend: every eligible backend is marked down")
	// ErrBackendUnreachable wraps an attempt's failure when the pool confirmed its backend absent:
	// the failure carried the absent hint and the backend's health probe, run right then, failed.
	ErrBackendUnreachable = errors.New("local backend confirmed unreachable by its health probe")
)

// IsBackendDown reports whether err is the pool's own verdict that a backend was down
// (ErrNoHealthyBackend or ErrBackendUnreachable).
func IsBackendDown(err error) bool {
	return errors.Is(err, ErrNoHealthyBackend) || errors.Is(err, ErrBackendUnreachable)
}

type backendHealth struct {
	known     bool
	up        bool
	since     time.Time
	lastErr   string
	kind      string
	failCount int
}

type healthTable struct {
	mu sync.Mutex
	m  map[string]*backendHealth
}

// HealthStatus is one backend's health, as the admin view shows it.
type HealthStatus struct {
	Backend   string    `json:"backend"`
	HealthURL string    `json:"health_url,omitempty"`
	Up        bool      `json:"up"`
	Known     bool      `json:"known"`
	Since     time.Time `json:"since,omitempty"`
	// LastError is the failure's text; it can quote a session's output, so Redacted drops it.
	LastError string `json:"last_error,omitempty"`
	// ErrorClass is <source>[:<kind>] from a fixed vocabulary, safe to show without
	// authentication: source probe_failed or call_failed; kind from the probe's typed error.
	ErrorClass string `json:"error_class,omitempty"`
	Drained    bool   `json:"drained"`
}

// Redacted is s without LastError and HealthURL (ErrorClass stays): what a caller that is not
// admin sees; the URL names an internal address.
func (s HealthStatus) Redacted() HealthStatus {
	s.LastError, s.HealthURL = "", ""
	return s
}

// errHTTPStatus is a probe answered with a status other than 2xx.
type errHTTPStatus int

func (e errHTTPStatus) Error() string { return fmt.Sprintf("HTTP %d", int(e)) }

// probeKind classifies a probe's failure from its type, never its text.
func probeKind(err error) string {
	var status errHTTPStatus
	var dns *net.DNSError
	var nerr net.Error
	switch {
	case err == nil:
		return ""
	case errors.As(err, &status):
		return "http_status"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection_refused"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	case errors.As(err, &dns):
		return "dns"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &nerr) && nerr.Timeout():
		return "timeout"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection_reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	}
	return ""
}

func (p *Policy) healthEntry(name string) *backendHealth {
	if p.health.m == nil {
		p.health.m = make(map[string]*backendHealth)
	}
	h := p.health.m[name]
	if h == nil {
		h = &backendHealth{}
		p.health.m[name] = h
	}
	return h
}

// BackendUp reports whether name may be routed to. Unknown is up: health only removes a backend on
// the pool's own evidence.
func (p *Policy) BackendUp(name string) bool {
	p.health.mu.Lock()
	defer p.health.mu.Unlock()
	h := p.health.m[name]
	return h == nil || !h.known || h.up
}

// setHealth records a verdict; source and probeErr word a down one.
func (p *Policy) setHealth(name string, up bool, source string, probeErr error, reason string) {
	p.health.mu.Lock()
	h := p.healthEntry(name)
	changed := !h.known || h.up != up
	h.known, h.up = true, up
	if up {
		h.failCount, h.lastErr, h.kind = 0, "", ""
	} else {
		h.lastErr = reason
		h.kind = source
		if k := probeKind(probeErr); k != "" {
			h.kind += ":" + k
		}
	}
	if changed {
		h.since = p.clock().UTC()
	}
	p.health.mu.Unlock()
	switch {
	case changed && up:
		p.logf("backends: %s is healthy; routing to it again", name)
	case changed:
		p.logf("backends: %s marked down (%s); routing skips it and local-only jobs wait queued", name, reason)
	}
}

// recordProbe applies one prober result, with the failure hysteresis.
func (p *Policy) recordProbe(name string, err error) {
	if err == nil {
		p.setHealth(name, true, "", nil, "")
		return
	}
	p.health.mu.Lock()
	h := p.healthEntry(name)
	h.failCount++
	n := h.failCount
	p.health.mu.Unlock()
	if n >= downAfterProbeFailures {
		p.setHealth(name, false, "probe_failed", err, fmt.Sprintf("health probe failed %dx: %v", n, err))
	}
}

// confirmBackendDown is the passive path. An attempt's failure that carries the absent hint
// triggers one probe of a backend that has a health_url, on a context detached from the job's (a
// spent job deadline must not read as a dead backend). A failed probe marks the backend down at
// once, so the jobs behind it do not wait for the prober, and wraps err with ErrBackendUnreachable;
// otherwise err comes back unchanged.
func (p *Policy) confirmBackendDown(ctx context.Context, b Backend, err error) error {
	if err == nil || b.HealthURL == "" || !runner.LooksAbsent(err) || errors.Is(err, ErrBackendUnreachable) {
		return err
	}
	perr := p.probeBackend(context.WithoutCancel(ctx), b)
	if perr == nil {
		return err
	}
	p.setHealth(b.Name, false, "call_failed", perr, "call failed and health probe failed: "+perr.Error()+": "+headSnippet(err.Error(), 200))
	return fmt.Errorf("%w (%s: %v): %w", ErrBackendUnreachable, b.Name, perr, err)
}

func (p *Policy) probeBackend(ctx context.Context, b Backend) error {
	reqCtx, cancel := context.WithTimeout(ctx, healthProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, b.HealthURL, nil)
	if err != nil {
		return err
	}
	resp, err := p.probeClient().Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errHTTPStatus(resp.StatusCode)
	}
	return nil
}

// ProbeOnce probes every backend that has a health_url, concurrently.
func (p *Policy) ProbeOnce(ctx context.Context) {
	var wg sync.WaitGroup
	for _, b := range p.Backends {
		if b.HealthURL == "" {
			continue
		}
		wg.Add(1)
		go func(b Backend) {
			defer wg.Done()
			p.recordProbe(b.Name, p.probeBackend(ctx, b))
		}(b)
	}
	wg.Wait()
}

// RunHealthProber probes at once, then every interval (0 or less: 15 seconds) until ctx ends.
func (p *Policy) RunHealthProber(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	p.ProbeOnce(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.ProbeOnce(ctx)
		}
	}
}

// AnyHealthy implements Pool.
func (p *Policy) AnyHealthy(affinity Affinity) bool {
	eligible := p.eligible(affinity)
	if len(eligible) == 0 {
		return true
	}
	for _, b := range eligible {
		if p.BackendUp(b.Name) {
			return true
		}
	}
	return false
}

// HealthSnapshot is every backend's health, sorted by name.
func (p *Policy) HealthSnapshot() []HealthStatus {
	drained := make(map[string]bool, len(p.Backends))
	for _, b := range p.Backends {
		drained[b.Name] = p.Drained(b.Name)
	}
	p.health.mu.Lock()
	defer p.health.mu.Unlock()
	out := make([]HealthStatus, 0, len(p.Backends))
	for _, b := range p.Backends {
		s := HealthStatus{Backend: b.Name, HealthURL: b.HealthURL, Up: true, Drained: drained[b.Name]}
		if h := p.health.m[b.Name]; h != nil && h.known {
			s.Known, s.Up, s.Since, s.LastError = true, h.up, h.since, h.lastErr
			s.ErrorClass = h.kind
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Backend < out[j].Backend })
	return out
}

// healthyOnly drops the backends marked down from order.
func (p *Policy) healthyOnly(order []Backend, rid string) (kept []Backend, skipped []string) {
	kept = make([]Backend, 0, len(order))
	for _, b := range order {
		if p.BackendUp(b.Name) {
			kept = append(kept, b)
		} else {
			skipped = append(skipped, b.Name)
		}
	}
	if len(skipped) > 0 {
		p.logf("backends: run=%s skipping down backend(s) %v", rid, skipped)
	}
	return kept, skipped
}

// headSnippet bounds an excerpt kept in a health record.
func headSnippet(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + " ...[truncated]"
}
