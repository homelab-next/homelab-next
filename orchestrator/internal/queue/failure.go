// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"unicode/utf8"

	"github.com/homelab-next/homelab-next/orchestrator/internal/backends"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// failingClass is the runner class of the leg whose failure ended the chain: the cloud leg's when
// it ran (ErrCloudFailed), else the local failure the pool decided on. It is read from the Result,
// never with runner.ClassOf on Call's error: when both legs failed, that error is the two joined,
// and ClassOf of it is the local leg's.
func failingClass(callErr error, res *backends.Result) runner.Class {
	if res == nil {
		return runner.Internal
	}
	if errors.Is(callErr, backends.ErrCloudFailed) {
		return res.CloudClass
	}
	return res.LocalClass
}

// ClassifyFailure is a failed attempt chain's failure class (store.Failure*): the failed event's
// reason, and what a caller's resubmit is checked against. callErr is the pool's Call error, res
// its Result. Only typed values decide: the pool's sentinels and the runner classes, with errors.Is
// (a spent budget in either leg counts) and from res (the failing leg's class).
//
//   - A spent budget first: the job's deadline (deadline), the turn cap (turn-cap), an attempt's
//     ceiling on a session still working (budget). Resubmitting buys the same end.
//   - stall: the failing leg stalled.
//   - backend-down: no cloud leg ran and the pool found every eligible backend down, or confirmed
//     the failing one down with its own probe.
//   - capacity: nothing could be attempted (every eligible backend leased or drained), the
//     gateway kept refusing the failing leg at its backend's concurrency cap, or the controller's
//     own context ended the session (a shutdown).
//   - timeout: a deadline of the controller's own on the way (not the job's).
//   - handler-error: everything else, a turn that ran and failed and a signal the controller did
//     not send included: nothing says a rerun fares better.
func ClassifyFailure(callErr error, res *backends.Result) string {
	switch {
	case errors.Is(callErr, backends.ErrJobDeadline):
		return store.FailureDeadline
	case errors.Is(callErr, backends.ErrTurnCapStops), errors.Is(callErr, runner.TurnCap):
		return store.FailureTurnCap
	case errors.Is(callErr, runner.TimeoutCeiling):
		return store.FailureBudget
	}
	class := failingClass(callErr, res)
	cloudFailed := errors.Is(callErr, backends.ErrCloudFailed)
	switch {
	case class == runner.Stalled:
		return store.FailureStall
	case !cloudFailed && backends.IsBackendDown(callErr):
		return store.FailureBackendDown
	case !cloudFailed && errors.Is(callErr, backends.ErrNoAttemptableBackend), class == runner.KilledByController,
		class == runner.ConcurrencyLimited:
		return store.FailureCapacity
	case class == runner.TurnFailed, class == runner.KilledExternally:
		return store.FailureHandlerError
	case errors.Is(callErr, context.DeadlineExceeded):
		return store.FailureTimeout
	}
	return store.FailureHandlerError
}

// classify is the failure class the job records: ClassifyFailure, except that a chain ended by
// the controller's own cancelled context (a shutdown: the pool reports it as its job deadline) is
// capacity, a fault of the environment. An operator's cancel ends the context too, but it moved
// the row first, so its class is never written.
func classify(ctx context.Context, callErr error, res *backends.Result) string {
	if errors.Is(ctx.Err(), context.Canceled) {
		return store.FailureCapacity
	}
	return ClassifyFailure(callErr, res)
}

// classReason is the reason a failed job records: its failure class, then the pool's bounded
// reason (the last local failure's class and an excerpt). Never the text of Call's error, which
// can quote whole sessions' output.
func classReason(class string, res *backends.Result) string {
	if res != nil && res.LocalFailedReason != "" {
		return class + ": " + res.LocalFailedReason
	}
	return class
}

// spentBudget reports whether callErr is a spent budget, in either leg: the job's deadline, an
// attempt's ceiling, the turn cap.
func spentBudget(callErr error) bool {
	return errors.Is(callErr, backends.ErrJobDeadline) || errors.Is(callErr, runner.TimeoutCeiling) ||
		errors.Is(callErr, runner.TurnCap) || errors.Is(callErr, backends.ErrTurnCapStops)
}

// spentSessionBudget is spentBudget but for the job's deadline: a session's own ceiling or turn
// cap. A shutdown ends the chain with the pool's ErrJobDeadline (a cancelled context), which is no
// budget the job spent.
func spentSessionBudget(callErr error) bool {
	return errors.Is(callErr, runner.TimeoutCeiling) || errors.Is(callErr, runner.TurnCap) || errors.Is(callErr, backends.ErrTurnCapStops)
}

// mayRetryAttempt reports whether a failed chain may run again under the profile's max_attempts:
// never once the job's context has ended (a cancel, its deadline) and never after a spent budget.
func mayRetryAttempt(ctx context.Context, callErr error) bool {
	return ctx.Err() == nil && !spentBudget(callErr)
}

// mayAutoRequeue reports whether a failed job may be retried automatically at all: never after a
// spent budget.
func mayAutoRequeue(callErr error) bool { return !spentBudget(callErr) }

// isSignalKill reports whether the failing leg was ended by a signal that is no budget's: the
// controller's own context (a shutdown) or a signal the controller did not send. Such a job is
// retried once automatically.
func isSignalKill(callErr error, res *backends.Result) bool {
	c := failingClass(callErr, res)
	return c == runner.KilledByController || c == runner.KilledExternally
}

// NewRunID is a fresh run id: 32 hex characters.
func NewRunID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // never fails: crypto/rand.Read aborts the process instead
	return hex.EncodeToString(b)
}

// truncatedMarker ends a text cut by boundText.
const truncatedMarker = "\n[truncated by the controller]"

// boundText is s, or its first bytes up to max (cut at a character boundary) with a marker when
// it is longer. It only bounds the text.
func boundText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max - len(truncatedMarker)
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + truncatedMarker
}
