// SPDX-License-Identifier: Apache-2.0

// Package api is the controller's job API over HTTP: submit, list, read and cancel jobs, plus the
// operators' admin routes. It takes the scheduler's and the pool's behaviour as injected
// functions and imports neither.
//
// Its safe defaults are refusals, never documentation: authentication is on unless the caller
// turns it off explicitly (Config.Unauthenticated), an unauthenticated API binds loopback only
// (NewServer refuses any other address), and the profiling routes are served only when asked for
// (Config.Pprof), behind the admin scope.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/metrics"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// Config is the API's dependencies.
type Config struct {
	// Store is the job store (required).
	Store *store.Store
	// AgentKnown reports whether an agent key has a profile (required; the scheduler's
	// HasProfile). A job naming an unknown agent key is refused (404) before anything is stored,
	// a resubmit included.
	AgentKnown func(agentKey string) bool
	// Auth checks every route's bearer token. Required unless Unauthenticated.
	Auth *Authenticator
	// Unauthenticated serves every route with no token. It must be set explicitly, and NewServer
	// then binds loopback only: a default must never depend on the bind address an operator
	// chose.
	Unauthenticated bool
	// Pprof serves /debug/pprof/* (admin scope).
	Pprof bool

	// CancelRun stops a cancelled job's live session (the scheduler's CancelRun); nil: a cancel
	// only moves the row.
	CancelRun func(runID string) bool
	// ReloadProfiles reloads the profiles (POST /admin/reload-profiles); nil answers 501.
	ReloadProfiles func() error
	// BackendStatus runs the site's status command (GET /admin/backend-status); nil answers 501.
	BackendStatus func(ctx context.Context) ([]byte, error)
	// BackendEligibility is the scheduler's BackendEligibility (GET /admin/backend-eligibility);
	// nil answers 501.
	BackendEligibility func(backend string) ([]BackendEligibilityEntry, error)
	// BackendHealth serves GET /admin/backend-health; full is false for a caller who may not see
	// raw error text. nil: not served.
	BackendHealth func(full bool) any
	// BackendDrain drains or undrains a backend (POST /admin/backends/{name}/drain|undrain);
	// ErrBackendNotFound answers 404. nil: not served.
	BackendDrain func(name string, drain bool) (status any, err error)
	// BackendInFlight serves GET /admin/backend-inflight. nil: not served.
	BackendInFlight func() any
	// Metrics writes GET /metrics. nil: not served.
	Metrics func(w io.Writer) error
}

// ErrBackendNotFound is what Config.BackendDrain returns for a name no backend has.
var ErrBackendNotFound = errors.New("no configured backend has that name")

// ErrInsecure is wrapped by NewHandler and NewServer for a configuration they refuse.
var ErrInsecure = errors.New("api: refused an insecure configuration")

// NewHandler is the API's routes, behind the authenticator unless Unauthenticated.
func NewHandler(cfg Config) (http.Handler, error) {
	switch {
	case cfg.Store == nil || cfg.AgentKnown == nil:
		return nil, errors.New("api: a store and an agent-key check are required")
	case cfg.Auth == nil && !cfg.Unauthenticated:
		return nil, fmt.Errorf("%w: authentication is on by default and no tokens were given (set Unauthenticated explicitly to serve without)", ErrInsecure)
	case cfg.Auth != nil && cfg.Unauthenticated:
		return nil, fmt.Errorf("%w: both an authenticator and Unauthenticated", ErrInsecure)
	}
	mux := newMux(cfg)
	if cfg.Auth == nil {
		return mux, nil
	}
	return cfg.Auth.Middleware(mux), nil
}

// CheckBind refuses an unauthenticated API on an address that is not loopback: an empty host, an
// unspecified address (0.0.0.0, ::) or any other host. Only an IP literal counts as loopback; a
// name is resolved by the system and could reach anything.
func CheckBind(addr string, authenticated bool) error {
	if authenticated {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: the address %q: %v", ErrInsecure, addr, err)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("%w: an unauthenticated API binds loopback only (an IP literal), not %q", ErrInsecure, addr)
}

// Server limits: an idle or slow client cannot hold a connection open for ever, and a header is
// bounded like a body.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 60 * time.Second
	writeTimeout      = 120 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 64 << 10
)

// NewServer is NewHandler on addr, refused for an unauthenticated API off loopback.
func NewServer(addr string, cfg Config) (*http.Server, error) {
	if err := CheckBind(addr, cfg.Auth != nil); err != nil {
		return nil, err
	}
	h, err := NewHandler(cfg)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr: addr, Handler: h,
		ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: readTimeout, WriteTimeout: writeTimeout,
		IdleTimeout: idleTimeout, MaxHeaderBytes: maxHeaderBytes,
	}, nil
}

func newMux(cfg Config) *http.ServeMux {
	s := cfg.Store
	mux := http.NewServeMux()
	mux.HandleFunc("POST /jobs", handleSubmit(s, cfg.AgentKnown))
	mux.HandleFunc("GET /jobs", handleListJobs(s))
	mux.HandleFunc("GET /jobs/{id}", handleGetJob(s))
	mux.HandleFunc("POST /jobs/{id}/cancel", handleCancel(s, cfg.CancelRun))
	mux.HandleFunc("POST /admin/reload-profiles", handleReloadProfiles(cfg.ReloadProfiles))
	mux.HandleFunc("GET /admin/backend-status", handleBackendStatus(cfg.BackendStatus))
	mux.HandleFunc("GET /admin/queue-summary", handleQueueSummary(s))
	mux.HandleFunc("GET /admin/backend-throughput", handleBackendThroughput(s))
	mux.HandleFunc("GET /admin/backend-eligibility", handleBackendEligibility(cfg.BackendEligibility))
	if cfg.BackendHealth != nil {
		authOff := cfg.Auth == nil
		mux.HandleFunc("GET /admin/backend-health", func(w http.ResponseWriter, r *http.Request) {
			full := authOff
			if p, ok := principalFrom(r.Context()); ok && p.admin {
				full = true
			}
			writeJSON(w, http.StatusOK, map[string]any{"backends": cfg.BackendHealth(full)})
		})
	}
	if cfg.BackendDrain != nil {
		mux.HandleFunc("POST /admin/backends/{name}/drain", handleBackendDrain(cfg.BackendDrain, true))
		mux.HandleFunc("POST /admin/backends/{name}/undrain", handleBackendDrain(cfg.BackendDrain, false))
	}
	if cfg.BackendInFlight != nil {
		mux.HandleFunc("GET /admin/backend-inflight", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"backends": cfg.BackendInFlight()})
		})
	}
	if cfg.Metrics != nil {
		mux.HandleFunc("GET /metrics", handleMetrics(cfg.Metrics))
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	if cfg.Pprof {
		mux.HandleFunc("GET /debug/pprof/", pprof.Index)
		mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	}
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// handleBackendDrain drains or undrains one backend and answers its new status; both are
// idempotent.
func handleBackendDrain(setDrained func(string, bool) (any, error), drain bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		status, err := setDrained(name, drain)
		if errors.Is(err, ErrBackendNotFound) {
			http.Error(w, "backend not found", http.StatusNotFound)
			return
		}
		if err != nil {
			log.Printf("api: drain %s=%v not changed: %v", name, drain, err)
			http.Error(w, "the drain state is unchanged: it could not be stored (see the controller's log)", http.StatusInternalServerError)
			return
		}
		log.Printf("api: drain %s=%v by %s", name, drain, callerOrAnonymous(r))
		writeJSON(w, http.StatusOK, status)
	}
}

func callerOrAnonymous(r *http.Request) string {
	if c := CallerFrom(r.Context()); c != "" {
		return c
	}
	return "an unauthenticated caller"
}

// handleMetrics renders into a buffer first, so a failed scrape is a clean 500.
func handleMetrics(write func(io.Writer) error) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		var buf bytes.Buffer
		if err := write(&buf); err != nil {
			log.Printf("api: metrics: %v", err)
			http.Error(w, "metrics unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", metrics.ContentType)
		_, _ = w.Write(buf.Bytes())
	}
}
