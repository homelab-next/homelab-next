// SPDX-License-Identifier: Apache-2.0

// Package runner is the controller's internal seam between its core (the backend pool, the queue)
// and whatever runs one agent session. The core builds a Session, hands it to a Runner, and
// decides fallback, retry and failure class from the typed classes below, never from error text.
// A runner owns its process, its environment and the classification of its own failures.
//
// This is not the public agent-runner contract: ADR-0026 decision 5 gives that contract its own
// ADR in stage 3, which may reshape this seam. Until then the only implementation in this module
// is the in-process fake (package runnertest).
package runner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Runner runs one agent session to completion. Cancelling ctx must stop the whole session (its
// process tree, for a subprocess runner) before Run returns: the controller releases a backend's
// capacity only once Run has returned. Run returns a non-nil *Result whenever it can, on failure
// too, since a failed session's usage report and stderr matter.
type Runner interface {
	Run(ctx context.Context, s Session) (*Result, error)
}

// The lanes a session runs in.
const (
	LaneReal   = "real"
	LaneShadow = "shadow"
)

// Session is everything one attempt needs. The pool fills Target and Limits per attempt (each
// local backend, a fallback, the cloud leg) and UsagePath per leg.
type Session struct {
	RunID    string
	AgentKey string
	Lane     string // LaneReal or LaneShadow; "" = unspecified
	Prompt   string
	// Toolsets are the lane's toolsets, opaque to the core.
	Toolsets []string
	// Servers, when non-nil, are the job's rendered MCP server grants (grants.Catalog.Render):
	// the runner gives the session exactly these servers. nil means the runner's own default
	// server set for Target.Home; an empty, non-nil map means none.
	Servers   map[string]Server
	Target    Target
	UsagePath string // where the runner writes the usage report; "" = none
	Limits    Limits
	// GatewayTag is the tag every model request of the session carries to the gateway
	// (inference.GatewayTag), so the gateway's usage records join the job's. "" = untagged. How
	// a runner passes it to its harness is the runner's business; it travels here, as a field,
	// never in ctx.
	GatewayTag string
}

// Server is one rendered MCP server grant, in no runner's format.
type Server struct {
	Command string
	Args    []string
	Env     map[string]string // nil when empty
	Timeout int               // seconds; 0 = the runner's default
}

// Target is where the session runs.
type Target struct {
	Backend string // the pool's backend name
	Cloud   bool   // the cloud leg
	// Home is the backend's runner configuration reference (backends.*.home), opaque to the core.
	Home string
	// Endpoint is the host:port the session's model connections go to, which progress liveness
	// watches; ProbeURLs are the backend's load and progress probes.
	Endpoint  string
	ProbeURLs []string
}

// Limits bound the session.
type Limits struct {
	Timeout      time.Duration // the attempt's ceiling; 0 = none beyond ctx
	StallTimeout time.Duration // 0 = no stall detection
	MaxTurns     int           // 0 = no turn cap
	Liveness     string        // "", "cpu" or "progress"
}

// Result is what one session produced.
type Result struct {
	Response  string
	Usage     map[string]any // the decoded usage report (tokens, calls, model, ...)
	SessionID string         // the runner's own session id, when it reports one
	ExitCode  int
	Stderr    string // bounded; captured on every exit, a clean one included
}

// Class is a failure class the core decides on (fallback, retry, the job's failure class). A
// Class is also an error value, so errors.Is(err, Stalled) reports whether err carries it.
type Class int

const (
	// Internal is no class the core acts on.
	Internal Class = iota
	// BackendFault: this attempt failed in a way attributable to its backend (a connection or
	// timeout signature, the backend busy past the interlock wait), so the pool tries the next
	// backend, then the cloud leg. It is a classification of one attempt from what that attempt
	// saw, made by the runner (or by the pool for its interlock wait). It is not the pool's
	// verdict that the backend is down: only a health probe the pool runs itself confirms an
	// outage (the pool's own unreachable error, package backends), and the pool marks a backend
	// unhealthy on that confirmation alone, never on a BackendFault.
	BackendFault
	// ContextExceeded: the backend had no room for this call; a backend with a larger window, or
	// the cloud leg, may.
	ContextExceeded
	// ToolCallParse: the backend's tool-call parser rejected a generated call; worth one retry on
	// the same backend.
	ToolCallParse
	// Stalled: the session made no progress for the stall timeout.
	Stalled
	// TimeoutCeiling: the attempt's ceiling fired on a session still making progress.
	TimeoutCeiling
	// TurnCap: the turn cap fired; a runaway, never retried.
	TurnCap
	// TurnFailed: the session ran and its turn failed.
	TurnFailed
	// KilledByController: the controller's own context ended the session (a cancel, a deadline).
	KilledByController
	// KilledExternally: a signal the controller did not send ended the session.
	KilledExternally
)

var classNames = [...]string{
	Internal:           "internal",
	BackendFault:       "backend-fault",
	ContextExceeded:    "context-exceeded",
	ToolCallParse:      "tool-call-parse",
	Stalled:            "stalled",
	TimeoutCeiling:     "timeout-ceiling",
	TurnCap:            "turn-cap",
	TurnFailed:         "turn-failed",
	KilledByController: "killed-by-controller",
	KilledExternally:   "killed-externally",
}

func (c Class) String() string {
	if c >= 0 && int(c) < len(classNames) {
		return classNames[c]
	}
	return fmt.Sprintf("class(%d)", int(c))
}

// Error makes a Class an errors.Is target.
func (c Class) Error() string { return "runner: " + c.String() }

// Error is a classified runner failure. Its text is exactly Err's, so classifying never changes
// what is logged or stored. One failure may carry several classes (one *Error wrapping another):
// errors.Is finds each, and ClassOf returns the first in pre-order.
type Error struct {
	Class Class
	Err   error
	// Absent marks a failure whose output suggests nothing was serving the backend (a refused
	// connection, a proxy answering for a stopped engine). It is a hint, not a verdict: the text
	// may quote the model's own output, so the pool confirms with its own probe before acting.
	Absent bool
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// Is matches a Class target equal to e.Class (never Internal), and the Absent hint.
func (e *Error) Is(target error) bool {
	if c, ok := target.(Class); ok {
		return c == e.Class && e.Class != Internal
	}
	return target == errAbsent && e.Absent
}

// Wrap returns err classified as c; nil for a nil err.
func Wrap(c Class, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Class: c, Err: err}
}

// MarkAbsent returns err carrying the Absent hint; nil for a nil err.
func MarkAbsent(err error) error {
	if err == nil {
		return nil
	}
	return &Error{Class: Internal, Err: err, Absent: true}
}

var errAbsent = errors.New("runner: backend absent")

// LooksAbsent reports whether any error in err's tree carries the Absent hint.
func LooksAbsent(err error) bool { return err != nil && errors.Is(err, errAbsent) }

// ClassOf returns the first class in err's tree, walked in pre-order (each error before what it
// wraps, a joined error's branches left to right: the order errors.Is and errors.As walk). A
// class is a classified *Error or a bare Class value (fmt.Errorf("...: %w", runner.Stalled)).
// Internal when there is none.
func ClassOf(err error) Class {
	if err == nil {
		return Internal
	}
	switch e := err.(type) {
	case *Error:
		if e.Class != Internal {
			return e.Class
		}
	case Class:
		if e != Internal {
			return e
		}
	}
	switch u := err.(type) {
	case interface{ Unwrap() error }:
		return ClassOf(u.Unwrap())
	case interface{ Unwrap() []error }:
		for _, w := range u.Unwrap() {
			if c := ClassOf(w); c != Internal {
				return c
			}
		}
	}
	return Internal
}

// AnswerChecker is an optional Runner capability: it judges a session that exited cleanly by its
// answer, and returns a classified error when the answer is a failure report (a context window
// exhausted, a tool-call parser rejection) rather than output. The pool applies it to local
// attempts, where such a failure moves the job to another backend or to the cloud leg.
type AnswerChecker interface {
	CheckAnswer(response string) error
}

// SplitToolsets turns a profile's comma-separated toolsets into Session.Toolsets.
func SplitToolsets(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// JoinToolsets is SplitToolsets' exact inverse.
func JoinToolsets(ts []string) string { return strings.Join(ts, ",") }
