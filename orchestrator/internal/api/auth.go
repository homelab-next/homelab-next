// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"syscall"

	"go.yaml.in/yaml/v3"
)

// Authentication. Each caller has its own bearer token; the controller holds only each token's
// SHA-256, so the tokens file is no credential store. Tokens are high-entropy random strings
// (openssl rand -hex 32), which is why an unsalted digest suffices, unlike for a password.
//
// Scopes:
//   - jobs: POST /jobs, GET /jobs, GET /jobs/{id}, POST /jobs/{id}/cancel, limited to the
//     caller's own jobs (store.Job.SubmittedBy): GET /jobs lists only them, and another caller's
//     run id is a 404.
//   - read: a read-only view of the fleet for dashboards: GET /jobs over every caller's jobs
//     (summaries only) and GET /admin/queue-summary.
//   - metrics: GET /metrics.
//   - admin: everything above for every caller's jobs, plus /admin/* and /debug/pprof/* (when
//     served at all).
//
// Open, no token: GET /healthz and GET /admin/backend-health (whose error text only an admin
// token sees), so a liveness probe and a status page need no credential.

// Scope names a class of routes a token may call.
type Scope string

const (
	ScopeJobs    Scope = "jobs"
	ScopeMetrics Scope = "metrics"
	ScopeAdmin   Scope = "admin"
	ScopeRead    Scope = "read"
)

// scopeOpen marks a route that needs no token.
const scopeOpen Scope = ""

// MaxTokensFileBytes bounds the tokens file.
const MaxTokensFileBytes = 1 << 20

// TokenEntry is one caller in the tokens file.
type TokenEntry struct {
	Caller string   `yaml:"caller"`
	SHA256 string   `yaml:"sha256"`
	Scopes []string `yaml:"scopes"`
}

type tokensFile struct {
	Tokens []TokenEntry `yaml:"tokens"`
}

type credential struct {
	caller string
	digest [sha256.Size]byte
	scopes map[Scope]bool
}

// Authenticator checks bearer tokens against a set of digests. Reload swaps the set atomically,
// so a rotation needs no restart (which would end every running job).
type Authenticator struct {
	path  string
	creds atomic.Pointer[[]credential]
}

// LoadAuthenticator reads the tokens file at path. It refuses an unreadable, oversized or
// malformed file (unknown keys included), one anyone but the controller or root could rewrite,
// an empty list, a digest that is not 64 hex characters, a digest two callers share, a caller
// with no name or no scope, and an unknown scope: authentication that is on must never start
// admitting nobody, or a mistyped entry.
func LoadAuthenticator(path string) (*Authenticator, error) {
	a := &Authenticator{path: path}
	if err := a.Reload(); err != nil {
		return nil, err
	}
	return a, nil
}

// Reload reads the tokens file again; on an error the previous set stays in force.
func (a *Authenticator) Reload() error {
	creds, err := parseTokensFile(a.path)
	if err != nil {
		return err
	}
	a.creds.Store(&creds)
	return nil
}

func parseTokensFile(path string) ([]credential, error) {
	if err := checkTokensFileOwnership(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read the api tokens file: %w", err)
	}
	defer f.Close()
	var buf bytes.Buffer
	if n, err := buf.ReadFrom(io.LimitReader(f, MaxTokensFileBytes+1)); err != nil {
		return nil, fmt.Errorf("read the api tokens file: %w", err)
	} else if n > MaxTokensFileBytes {
		return nil, fmt.Errorf("the api tokens file %s is larger than %d bytes", path, MaxTokensFileBytes)
	}
	var tf tokensFile
	dec := yaml.NewDecoder(&buf)
	dec.KnownFields(true)
	if err := dec.Decode(&tf); err != nil {
		return nil, fmt.Errorf("parse the api tokens file %s: %w", path, err)
	}
	if len(tf.Tokens) == 0 {
		return nil, fmt.Errorf("the api tokens file %s lists no tokens", path)
	}
	seen := map[[sha256.Size]byte]string{}
	out := make([]credential, 0, len(tf.Tokens))
	for i, t := range tf.Tokens {
		if strings.TrimSpace(t.Caller) == "" {
			return nil, fmt.Errorf("api tokens file %s: entry %d has no caller", path, i)
		}
		raw, err := hex.DecodeString(strings.TrimSpace(t.SHA256))
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("api tokens file %s: caller %q: sha256 must be 64 hex characters", path, t.Caller)
		}
		var d [sha256.Size]byte
		copy(d[:], raw)
		if prev, dup := seen[d]; dup {
			return nil, fmt.Errorf("api tokens file %s: callers %q and %q share one token", path, prev, t.Caller)
		}
		seen[d] = t.Caller
		if len(t.Scopes) == 0 {
			return nil, fmt.Errorf("api tokens file %s: caller %q has no scopes", path, t.Caller)
		}
		scopes := map[Scope]bool{}
		for _, s := range t.Scopes {
			switch Scope(s) {
			case ScopeJobs, ScopeMetrics, ScopeAdmin, ScopeRead:
				scopes[Scope(s)] = true
			default:
				return nil, fmt.Errorf("api tokens file %s: caller %q: unknown scope %q (want jobs, read, metrics or admin)", path, t.Caller, s)
			}
		}
		out = append(out, credential{caller: t.Caller, digest: d, scopes: scopes})
	}
	return out, nil
}

// checkTokensFileOwnership refuses a tokens file someone other than the controller could rewrite:
// not a regular file, group- or world-writable, or owned by a uid that is neither the
// controller's nor root's. It holds only digests, but whoever edits it can mint an admin token.
func checkTokensFileOwnership(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("read the api tokens file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("the api tokens file %s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("the api tokens file %s is group- or world-writable (mode %#o); chmod go-w it", path, perm)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if uid := int(st.Uid); uid != 0 && uid != os.Getuid() {
			return fmt.Errorf("the api tokens file %s is owned by uid %d, not the controller (uid %d) or root", path, uid, os.Getuid())
		}
	}
	return nil
}

// authenticate returns the credential whose digest matches token, comparing every entry in
// constant time whatever matched before, so the time taken says nothing about which matched.
func (a *Authenticator) authenticate(token string) *credential {
	creds := a.creds.Load()
	if creds == nil || token == "" {
		return nil
	}
	d := sha256.Sum256([]byte(token))
	var match *credential
	for i := range *creds {
		c := &(*creds)[i]
		if subtle.ConstantTimeCompare(d[:], c.digest[:]) == 1 {
			match = c
		}
	}
	return match
}

func (c *credential) principal() principal {
	return principal{caller: c.caller, admin: c.scopes[ScopeAdmin], read: c.scopes[ScopeRead]}
}

func (c *credential) allows(s Scope) bool { return c.scopes[ScopeAdmin] || c.scopes[s] }

// RouteScope is the scope a request needs. Any route not named here is admin: a route added
// later fails closed.
func RouteScope(method, path string) Scope {
	switch {
	case path == "/healthz":
		return scopeOpen
	case (method == http.MethodGet || method == http.MethodHead) && path == "/admin/backend-health":
		return scopeOpen
	case path == "/metrics":
		return ScopeMetrics
	case path == "/jobs" || strings.HasPrefix(path, "/jobs/"):
		return ScopeJobs
	}
	return ScopeAdmin
}

// readOnlyRoute reports whether a read-scope token may call the route.
func readOnlyRoute(method, path string) bool {
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	return path == "/jobs" || path == "/admin/queue-summary"
}

type callerKey struct{}

// principal is the authenticated identity a request carries.
type principal struct {
	caller string
	admin  bool
	read   bool
}

// CallerFrom returns the authenticated caller, or "" with auth off or on an open route.
func CallerFrom(ctx context.Context) string {
	if p, ok := ctx.Value(callerKey{}).(principal); ok {
		return p.caller
	}
	return ""
}

func principalFrom(ctx context.Context) (principal, bool) {
	p, ok := ctx.Value(callerKey{}).(principal)
	return p, ok
}

// mayAccessJob reports whether the request may read or cancel a job owned by submittedBy: always
// with auth off, always for admin, otherwise only its submitter.
func mayAccessJob(ctx context.Context, submittedBy string) bool {
	p, ok := principalFrom(ctx)
	if !ok {
		return true
	}
	return p.admin || (p.caller != "" && p.caller == submittedBy)
}

// listOwnerFilter is the owner GET /jobs keeps: none with auth off, for admin and for a read
// token; else the caller's own.
func listOwnerFilter(ctx context.Context) (owner string, restricted bool) {
	p, ok := principalFrom(ctx)
	if !ok || p.admin || p.read {
		return "", false
	}
	return p.caller, true
}

const realm = `Bearer realm="orchestrator"`

// Middleware puts next behind the bearer tokens: 401 for a missing or unknown token, 403 for a
// valid one without the route's scope. On an open route a valid token still names the caller
// (an admin sees the backend health's error text); an invalid one is ignored there.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		need := RouteScope(r.Method, r.URL.Path)
		token, hasToken := bearerToken(r)
		if need == scopeOpen {
			if hasToken {
				if c := a.authenticate(token); c != nil {
					r = r.WithContext(context.WithValue(r.Context(), callerKey{}, c.principal()))
				}
			}
			next.ServeHTTP(w, r)
			return
		}
		if !hasToken {
			w.Header().Set("WWW-Authenticate", realm)
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		c := a.authenticate(token)
		if c == nil {
			log.Printf("api: refused an unknown token for %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", realm+`, error="invalid_token"`)
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return
		}
		if !c.allows(need) && !(c.scopes[ScopeRead] && readOnlyRoute(r.Method, r.URL.Path)) {
			log.Printf("api: caller %s lacks scope %s for %s %s", c.caller, need, r.Method, r.URL.Path)
			http.Error(w, fmt.Sprintf("the token of %s lacks the %s scope", c.caller, need), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, c.principal())))
	})
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	return tok, tok != ""
}
