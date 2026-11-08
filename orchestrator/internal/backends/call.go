// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/homelab-next/homelab-next/orchestrator/internal/inference"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
)

// sameBackendRetries is how many more times one backend is asked after an attempt classified
// runner.ToolCallParse before the chain moves on: such a rejection is often intermittent, and a
// local retry costs no cloud spend, while a deterministic one exhausts the retries and moves on.
const sameBackendRetries = 2

// Locality is where a job may run: its profile's local_only, as a type, so a call cannot pass the
// flag inverted by accident. The zero value is LocalOnly: a caller that sets nothing never starts a
// cloud leg (and spends nothing outside the lab).
type Locality int

const (
	// LocalOnly: local backends only; the cloud leg never runs.
	LocalOnly Locality = iota
	// CloudFallback: the cloud leg runs after the local attempts when the gate allows.
	CloudFallback
)

// LocalityOf is a profile's local_only as a Locality.
func LocalityOf(localOnly bool) Locality {
	if localOnly {
		return LocalOnly
	}
	return CloudFallback
}

func (l Locality) String() string {
	if l == CloudFallback {
		return "cloud-fallback"
	}
	return "local-only"
}

// The pool's own errors.
var (
	// ErrJobDeadline: the job's context ended (its deadline, or a cancel) before the chain did. No
	// further leg starts, the cloud leg included.
	ErrJobDeadline = errors.New("job deadline exceeded before the attempt chain finished")
	// ErrNoAttemptableBackend: the local order was empty without any attempt (every eligible
	// backend leased to another run, drained, or full at its max_concurrent), so nothing ran.
	ErrNoAttemptableBackend = errors.New("every eligible local backend is exclusively leased, drained or at its max_concurrent; no local attempt was possible")
	// ErrNoLocalCapacity: the affinity excludes every configured local backend. Like an outage, it
	// moves the job to the cloud leg unless the job is local-only.
	ErrNoLocalCapacity = errors.New("backend affinity excluded every configured local backend")
	// ErrNotAttributable: the local failure is not the backend's (a configuration or environment
	// problem a cloud leg cannot fix), so the cloud leg is not started.
	ErrNotAttributable = errors.New("the local failure is not attributable to the backend; the cloud leg is not started")
	// ErrLocalOnly: every local attempt failed and the profile is local-only.
	ErrLocalOnly = errors.New("every local attempt failed and the profile is local-only; the cloud leg is not started")
	// ErrNoCloudBackend: every local attempt failed and the pool has no cloud leg (no CloudHome).
	ErrNoCloudBackend = errors.New("every local attempt failed and no cloud backend is configured")
	// ErrCloudFailed: the cloud leg ran and failed too. Its error wraps both legs': errors.Is finds
	// either leg's class, but runner.ClassOf of it is the local leg's, so read a leg's class from
	// Result.LocalClass and Result.CloudClass.
	ErrCloudFailed = errors.New("the cloud leg failed after the local failure")
	// ErrTurnCapStops: an attempt hit the turn cap, a runaway another backend would repeat; the
	// chain stops there.
	ErrTurnCapStops = errors.New("the turn cap ended the attempt; not retried on another backend or the cloud")
)

// Attempt is one leg of a chain, classified on its own, before any leg's error is joined with
// another's.
type Attempt struct {
	Backend string // "" for the cloud leg
	Cloud   bool
	// Failed is false for the attempt that produced the answer.
	Failed bool
	// Class is runner.ClassOf of this leg's own error (its outermost class), for the trail only;
	// Internal on success or for no class. Decisions read every class in the leg's error.
	Class runner.Class
}

// Result is one Call's outcome: the session result of the attempt that produced it (or of the last
// one, on failure), and the chain's trail.
type Result struct {
	runner.Result
	UsedCloud     bool
	LocalAttempts int
	// LocalFailedReason is the last local failure, bounded: its outermost class, then at most
	// reasonMaxBytes of its text. The text can quote a session's output, so LocalFailedDetail, its
	// whole text, is for an admin-only view.
	LocalFailedReason string
	LocalFailedDetail string
	LocalBackendUsed  string // the local backend that answered; "" otherwise
	// LocalClass is runner.ClassOf of the local failure the cloud gate decided on, CloudClass of
	// the cloud leg's, for reporting; Internal when there was none, or it had no class.
	LocalClass runner.Class
	CloudClass runner.Class
	// Attempts are every leg, in order.
	Attempts []Attempt
}

// attributable reports whether one leg's failure is its backend's: the only grounds for starting
// the cloud leg, besides a capacity gap (no local backend qualifies, or every one ran out of
// context or produced tool calls its parser rejected; the cloud leg runs neither). A session still
// working when its ceiling fired, one stalled on a wedged dependency, a turn the runner started and
// could not complete, a connection or busy fault, and a backend the pool itself found down all
// count. Any such class anywhere in the leg's error counts (errors.Is), not only its outermost: a
// runner wraps what it saw first under what ended the session (a kill around a connection fault,
// a failed turn around a context exhaustion), and every class it recorded is a fact about the leg.
func attributable(err error) bool {
	for _, c := range []runner.Class{runner.BackendFault, runner.Stalled, runner.TimeoutCeiling, runner.TurnFailed,
		runner.ContextExceeded, runner.ToolCallParse} {
		if errors.Is(err, c) {
			return true
		}
	}
	return IsBackendDown(err) || errors.Is(err, ErrNoLocalCapacity)
}

// Call runs one job's attempt chain. Each eligible local backend gets one attempt, in order: the
// reserved backend first when the caller reserved one (its slot is counted already), otherwise a
// fresh pick (weighted round-robin, then least loaded). A backend leased to another run, drained,
// or marked down is skipped. After a failure, by the classes anywhere in that leg's error
// (errors.Is), checked in this order:
//
//   - runner.TurnCap stops the chain (ErrTurnCapStops);
//   - runner.ToolCallParse asks the same backend again, up to sameBackendRetries times;
//   - runner.ContextExceeded puts the remaining backends in order of declared window, biggest first;
//   - anything else moves to the next backend, whatever its class: a second local attempt costs
//     nothing a cloud leg would.
//
// A clean exit is checked by the runner's AnswerChecker, when it has one: an answer that reports a
// failure is that failure. Only local attempts are checked; the cloud leg's answer is the job's.
//
// When every local attempt failed, the cloud leg runs only when locality is CloudFallback, the pool
// has a CloudHome and the last local failure is attributable (attributable). The job's deadline
// (JobLimit, applied here, or the caller's) ends the chain between legs with ErrJobDeadline.
//
// s carries the run's identity, prompt, toolsets, servers and the base usage path; Call sets each
// attempt's Target, Limits and its own leg's UsagePath (LegUsagePath). It returns a non-nil
// *Result on every path.
func (p *Policy) Call(ctx context.Context, s runner.Session, locality Locality, affinity Affinity, reserved string) (*Result, error) {
	if p.JobLimit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.JobLimit)
		defer cancel()
	}
	if p.Runner == nil {
		return &Result{}, errors.New("backends: the pool has no runner; no attempt can run")
	}
	rid := runLabel(s.RunID)
	base := s.UsagePath
	legs := 0
	nextUsagePath := func() string {
		legs++
		return LegUsagePath(base, legs)
	}
	out := &Result{}
	deadline := func(lastErr error) (*Result, error) {
		reason := jobDeadlineReason(ctx, lastErr)
		out.LocalFailedReason = headSnippet(reason, reasonMaxBytes)
		out.LocalFailedDetail = reason
		return out, fmt.Errorf("%w: %s", ErrJobDeadline, reason)
	}

	var lastErr error
	eligible := p.eligible(affinity)
	var order []Backend
	switch {
	case len(eligible) == 0:
		lastErr = fmt.Errorf("%w (require_tags=%v exclude_backends=%v min_context=%d against %d configured backend(s))",
			ErrNoLocalCapacity, affinity.RequireTags, affinity.ExcludeBackends, affinity.MinContext, len(p.Backends))
	case reserved != "":
		// The caller ran selectOrder once, when it reserved; picking again would advance the
		// round-robin twice for one dispatch.
		order = moveToFront(eligible, reserved)
	default:
		order = p.selectOrder(ctx, eligible)
	}
	order = p.filterForExclusive(order, affinity, reserved, s.RunID)
	order, down := p.healthyOnly(order, rid)
	if len(order) == 0 && len(down) > 0 && lastErr == nil {
		lastErr = fmt.Errorf("%w (%v)", ErrNoHealthyBackend, down)
	}
	if len(order) > 1 {
		names := make([]string, len(order))
		for i, b := range order {
			names[i] = b.Name
		}
		p.logf("backends: run=%s attempt order %v", rid, names)
	}

	for i := 0; i < len(order); i++ {
		backend := order[i]
		var err error
		var res *Result
		// The reserved backend's slot is the caller's reservation, its same-backend retries
		// included (they run one after another). Any other backend is attempted only when it has
		// a free slot at its max_concurrent by the pool's own in-flight count, the count a
		// reservation's claim shares (probe load and the token budget are admission's), taken for
		// the attempt: a fallover never takes a slot another job's reservation holds.
		counted := backend.Name == reserved
		// The order was filtered for leases and drains when the chain began; an earlier attempt
		// can take long, so a backend leased to another run or drained since is skipped too.
		if !counted && p.exclusivelyBlocked(backend.Name, s.RunID) {
			p.logf("backends: run=%s backend=%s was leased or drained since the chain began; not attempted", rid, backend.Name)
			continue
		}
		if !counted && !p.takeSlot(backend) {
			p.logf("backends: run=%s backend=%s is at its max_concurrent (%d); not attempted", rid, backend.Name, backend.MaxConcurrent)
			continue
		}
		for retry := 0; retry <= sameBackendRetries; retry++ {
			if ctx.Err() != nil {
				if !counted {
					p.giveSlot(backend)
				}
				return deadline(lastErr)
			}
			out.LocalAttempts++
			res, err = p.callLocal(ctx, backend, s, nextUsagePath())
			if err != nil {
				err = p.confirmBackendDown(ctx, backend, err)
			} else if ac, ok := p.Runner.(runner.AnswerChecker); ok {
				err = ac.CheckAnswer(res.Response)
			}
			class := runner.ClassOf(err)
			out.Attempts = append(out.Attempts, Attempt{Backend: backend.Name, Failed: err != nil, Class: class})
			out.Result = res.Result
			if err == nil {
				if !counted {
					p.giveSlot(backend)
				}
				out.LocalBackendUsed = backend.Name
				if len(order) > 1 || retry > 0 {
					p.logf("backends: run=%s backend=%s attempt=%d retry=%d succeeded", rid, backend.Name, out.LocalAttempts, retry)
				}
				return out, nil
			}
			p.logf("backends: run=%s backend=%s attempt=%d retry=%d failed (%s): %s", rid, backend.Name, out.LocalAttempts, retry, class, headSnippet(err.Error(), reasonMaxBytes))
			if errors.Is(err, runner.TurnCap) {
				if !counted {
					p.giveSlot(backend)
				}
				setLocalFailure(out, err)
				out.LocalClass = class
				return out, fmt.Errorf("%w: %w", ErrTurnCapStops, err)
			}
			if !errors.Is(err, runner.ToolCallParse) {
				break
			}
		}
		if !counted {
			p.giveSlot(backend)
		}
		lastErr = err
		if errors.Is(err, runner.ContextExceeded) && i+1 < len(order) {
			rest := order[i+1:]
			sort.SliceStable(rest, func(a, b int) bool { return rest[a].MaxContext > rest[b].MaxContext })
			p.logf("backends: run=%s backend=%s ran out of context; the rest go biggest window first", rid, backend.Name)
		}
	}

	if ctx.Err() != nil {
		return deadline(lastErr)
	}
	if lastErr == nil {
		lastErr = ErrNoAttemptableBackend
	}
	setLocalFailure(out, lastErr)
	out.LocalClass = runner.ClassOf(lastErr)
	switch {
	case locality != CloudFallback:
		return out, fmt.Errorf("%w: %w", ErrLocalOnly, lastErr)
	case p.CloudHome == "":
		return out, fmt.Errorf("%w: %w", ErrNoCloudBackend, lastErr)
	case !attributable(lastErr):
		return out, fmt.Errorf("%w: %w", ErrNotAttributable, lastErr)
	}

	cs := s
	// The cloud leg has no endpoint or probes: progress liveness never watches it for socket
	// traffic, whatever the configuration names for it.
	cs.Target = runner.Target{Cloud: true, Home: p.CloudHome}
	cs.Limits = p.Limits
	cs.UsagePath = nextUsagePath()
	rr, err := p.Runner.Run(ctx, cs)
	out.UsedCloud = true
	out.Result = runner.Result{}
	if rr != nil {
		out.Result = *rr
	}
	out.CloudClass = runner.ClassOf(err)
	out.Attempts = append(out.Attempts, Attempt{Cloud: true, Failed: err != nil, Class: out.CloudClass})
	if err != nil {
		return out, fmt.Errorf("%w (local: %w): %w", ErrCloudFailed, lastErr, err)
	}
	return out, nil
}

// LegUsagePath is the usage path of the n-th (1-based) session of one Call: base for the first, so
// a one-leg call writes the file it names, and base with ".legN" before its ".json" suffix after,
// beside it, so one glob on the run id finds every leg. An empty base stays empty.
func LegUsagePath(base string, n int) string {
	if base == "" || n <= 1 {
		return base
	}
	return strings.TrimSuffix(base, ".json") + fmt.Sprintf(".leg%d.json", n)
}

// callLocal runs one attempt on backend, whose slot the caller holds (its reservation, or takeSlot)
// for the whole attempt, the wait for the interlock included. It never returns a nil *Result.
func (p *Policy) callLocal(ctx context.Context, backend Backend, s runner.Session, usagePath string) (*Result, error) {
	if backend.NeedsInterlock {
		waitCtx := ctx
		if p.InterlockWait > 0 {
			var cancel context.CancelFunc
			waitCtx, cancel = context.WithTimeout(ctx, p.InterlockWait)
			defer cancel()
		}
		held, err := p.Interlock.Acquire(waitCtx)
		if err != nil {
			err = fmt.Errorf("acquire the interlock for %s: %w", backend.Name, err)
			switch {
			case !errors.Is(err, inference.ErrWaitEnded):
				// The lock file itself was refused: the site's configuration, not the backend.
			case ctx.Err() != nil:
				// The job ended while it waited: a cancel or the job's deadline, not the backend.
				err = runner.Wrap(runner.KilledByController, err)
			case waitCtx.Err() != nil:
				// Busy past the pool's bound: the backend's, like a failed connection.
				err = runner.Wrap(runner.BackendFault, err)
			}
			return &Result{}, err
		}
		defer func() {
			if rerr := held.Release(); rerr != nil {
				p.logf("backends: release the interlock for %s: %v", backend.Name, rerr)
			}
		}()
	}
	s.Target = runner.Target{
		Backend:   backend.Name,
		Home:      backend.Home,
		Endpoint:  backend.Endpoint,
		ProbeURLs: slices.Clone(backend.LoadProbeURLs),
	}
	s.Limits = p.Limits
	s.UsagePath = usagePath
	rr, err := p.Runner.Run(ctx, s)
	if rr == nil {
		return &Result{}, err
	}
	return &Result{Result: *rr}, err
}

// reasonMaxBytes bounds the failure text kept in a reason or a log line.
const reasonMaxBytes = 400

// setLocalFailure records err as the last local failure: bounded in the reason, whole in the detail.
func setLocalFailure(out *Result, err error) {
	text := err.Error()
	out.LocalFailedReason = runner.ClassOf(err).String() + ": " + headSnippet(text, reasonMaxBytes)
	out.LocalFailedDetail = text
}

// runLabel names a run in a log line: "-" for none.
func runLabel(runID string) string {
	if runID == "" {
		return "-"
	}
	return runID
}

func jobDeadlineReason(ctx context.Context, lastErr error) string {
	r := fmt.Sprintf("job deadline exceeded (%v)", ctx.Err())
	if lastErr != nil {
		r += "; last attempt: " + lastErr.Error()
	}
	return r
}
