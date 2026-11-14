// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"sort"
	"strings"
)

// Caller kinds.
const (
	callerKey = iota
	callerAdmin
	callerTelemetry
)

// AdminAlias and TelemetryAlias are the key aliases the admin and telemetry keys are recorded
// under: not slugs, so they can never collide with a configured key.
const (
	AdminAlias     = "@admin"
	TelemetryAlias = "@telemetry"
)

// MinClientKeyBytes is the shortest value a caller key may have: keys[] and telemetry (ADR-0038 d2), and
// the admin key too, which can call every role.
const MinClientKeyBytes = 32

// caller is one authenticated identity.
type caller struct {
	kind   int
	key    *Key // kind == callerKey
	env    string
	digest [sha256.Size]byte
}

func (c *caller) alias() string {
	switch c.kind {
	case callerKey:
		return c.key.Alias
	case callerTelemetry:
		return TelemetryAlias
	}
	return AdminAlias
}

func (c *caller) owner() string {
	if c.kind == callerKey {
		return c.key.Owner
	}
	return c.alias()
}

// sender is the caller's sending TLP ceiling: the key's, and red for the admin key (ADR-0038 d5).
func (c *caller) sender() Label {
	if c.kind == callerKey {
		return c.key.ceiling
	}
	return Red
}

// Secrets holds what the gateway reads from its environment at start: the SHA-256 digest of
// every caller key, and the provider API key values deployments send upstream.
type Secrets struct {
	callers  []*caller
	upstream map[string]string
}

// LoadSecrets reads every *_env the config names through lookup (os.LookupEnv in production). A
// missing or empty value is an error naming the variable, never a value. A client key shorter
// than MinClientKeyBytes (the admin key included), and two callers with the same value, are refused (ADR-0038 d2). Caller keys are
// kept only as SHA-256 digests; provider keys are kept as values, since they are sent upstream.
func LoadSecrets(c *Config, lookup func(string) (string, bool)) (*Secrets, error) {
	var p problems
	s := &Secrets{upstream: map[string]string{}}
	read := func(env string) (string, bool) {
		v, ok := lookup(env)
		if !ok || v == "" {
			p.add("environment variable %s is missing or empty", env)
			return "", false
		}
		return v, true
	}
	addCaller := func(kind int, key *Key, env string) {
		if v, ok := read(env); ok {
			if len(v) < MinClientKeyBytes {
				p.add("environment variable %s holds a key shorter than %d bytes", env, MinClientKeyBytes)
			}
			s.callers = append(s.callers, &caller{kind: kind, key: key, env: env, digest: sha256.Sum256([]byte(v))})
		}
	}
	addCaller(callerAdmin, nil, c.AdminKeyEnv)
	if c.TelemetryReader != nil {
		addCaller(callerTelemetry, nil, c.TelemetryReader.KeyEnv)
	}
	for _, k := range c.Keys {
		addCaller(callerKey, k, k.KeyEnv)
	}
	for _, alias := range sortedKeys(c.Roles) {
		for _, d := range c.Roles[alias].Deployments {
			if d.APIKeyEnv == nil {
				continue
			}
			if _, done := s.upstream[*d.APIKeyEnv]; done {
				continue
			}
			if v, ok := read(*d.APIKeyEnv); ok {
				s.upstream[*d.APIKeyEnv] = v
			}
		}
	}
	for i, a := range s.callers {
		for _, b := range s.callers[i+1:] {
			if a.digest == b.digest {
				p.add("environment variables %s and %s hold the same key", a.env, b.env)
			}
		}
	}
	if len(p) > 0 {
		sort.Strings(p)
		return nil, &ConfigError{p}
	}
	return s, nil
}

// authenticate finds the caller whose key is the request's bearer token. Every digest is
// compared, in constant time, whatever matches.
func (s *Secrets) authenticate(r *http.Request) *caller {
	h := r.Header.Get("Authorization")
	scheme, token, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return nil
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	d := sha256.Sum256([]byte(token))
	var found *caller
	for _, c := range s.callers {
		if subtle.ConstantTimeCompare(d[:], c.digest[:]) == 1 {
			found = c
		}
	}
	return found
}

func (s *Secrets) upstreamKey(d *Deployment) string {
	if d.APIKeyEnv == nil {
		return ""
	}
	return s.upstream[*d.APIKeyEnv]
}
