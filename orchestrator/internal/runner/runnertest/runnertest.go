// SPDX-License-Identifier: Apache-2.0

// Package runnertest is an in-process runner.Runner for tests: scripted answers and classified
// failures, a session that blocks until released or cancelled, and a hook that runs when a
// blocked session is killed. It starts no process, so a test of the pool or the queue can drive
// every failure class without a stand-in program on PATH. Process semantics (a kill reaching the
// whole tree, a signal, an orphan after a restart) need a real subprocess runner instead.
package runnertest

import (
	"context"
	"errors"
	"sync"

	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
)

// Step is one scripted session.
type Step func(ctx context.Context, s runner.Session) (*runner.Result, error)

// Runner runs each session through the next Step of Script: the last step repeats once the
// script is spent, and an empty script answers "ok". It records every session it is given. Safe
// for concurrent use; the order of concurrent sessions is the order Run took its lock.
type Runner struct {
	Script []Step
	// AnswerCheck is what CheckAnswer (runner.AnswerChecker) runs; nil accepts every answer.
	AnswerCheck func(response string) error

	mu       sync.Mutex
	sessions []runner.Session
}

var (
	_ runner.Runner        = (*Runner)(nil)
	_ runner.AnswerChecker = (*Runner)(nil)
)

// New returns a Runner playing steps in order.
func New(steps ...Step) *Runner { return &Runner{Script: steps} }

// Run implements runner.Runner.
func (r *Runner) Run(ctx context.Context, s runner.Session) (*runner.Result, error) {
	r.mu.Lock()
	i := len(r.sessions)
	r.sessions = append(r.sessions, s)
	var step Step
	switch {
	case len(r.Script) == 0:
		step = Answer("ok")
	case i < len(r.Script):
		step = r.Script[i]
	default:
		step = r.Script[len(r.Script)-1]
	}
	r.mu.Unlock()
	return step(ctx, s)
}

// Sessions returns a copy of every session Run was given, in order.
func (r *Runner) Sessions() []runner.Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]runner.Session(nil), r.sessions...)
}

// CheckAnswer implements runner.AnswerChecker.
func (r *Runner) CheckAnswer(response string) error {
	if r.AnswerCheck == nil {
		return nil
	}
	return r.AnswerCheck(response)
}

// Answer is a clean session answering response.
func Answer(response string) Step {
	return func(context.Context, runner.Session) (*runner.Result, error) {
		return &runner.Result{Response: response, Usage: map[string]any{}}, nil
	}
}

// Fail is a session failing with msg, classified as class.
func Fail(class runner.Class, msg string) Step {
	return func(context.Context, runner.Session) (*runner.Result, error) {
		return &runner.Result{Usage: map[string]any{}, ExitCode: 1}, runner.Wrap(class, errors.New(msg))
	}
}

// Block is a session that runs until release is closed (it then answers response) or ctx is done
// (onKill, when non-nil, then runs, and the session fails as runner.KilledByController). Either
// way it has returned before Run does, as the seam requires.
func Block(release <-chan struct{}, response string, onKill func(runner.Session)) Step {
	return func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		select {
		case <-release:
			return &runner.Result{Response: response, Usage: map[string]any{}}, nil
		case <-ctx.Done():
			if onKill != nil {
				onKill(s)
			}
			return &runner.Result{Usage: map[string]any{}, ExitCode: -1},
				runner.Wrap(runner.KilledByController, errors.New("runnertest: session killed: "+ctx.Err().Error()))
		}
	}
}

// On picks a step per session by its target: the backend name, or "cloud" for the cloud leg;
// fallback for any other.
func On(byTarget map[string]Step, fallback Step) Step {
	return func(ctx context.Context, s runner.Session) (*runner.Result, error) {
		key := s.Target.Backend
		if s.Target.Cloud {
			key = "cloud"
		}
		if st, ok := byTarget[key]; ok {
			return st(ctx, s)
		}
		return fallback(ctx, s)
	}
}
