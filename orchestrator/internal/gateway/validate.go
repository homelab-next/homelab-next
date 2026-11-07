// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	slugRE    = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)
	envRE     = regexp.MustCompile(`^HNX_SECRET_[A-Z0-9_]+$`)
	versionRE = regexp.MustCompile(`^([0-9]+)\.([0-9]+)$`)
	profileRE = regexp.MustCompile(`^profile:[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

type problems []string

func (p *problems) add(format string, a ...any) { *p = append(*p, fmt.Sprintf(format, a...)) }

func (c *Config) validate() []string {
	var p problems
	if m := versionRE.FindStringSubmatch(c.Version); m == nil || m[1] != "1" {
		p.add("version %q: this gateway reads contract version 1.x", c.Version)
	}
	if c.Name != "" && !slugRE.MatchString(c.Name) {
		p.add("name %q is not a slug", c.Name)
	}
	checkEnv(&p, "admin_key_env", c.AdminKeyEnv)
	if c.TelemetryReader != nil {
		checkEnv(&p, "telemetry_reader.key_env", c.TelemetryReader.KeyEnv)
	}
	if len(c.Roles) == 0 {
		p.add("roles: at least one role is required")
	}
	for _, alias := range sortedKeys(c.Roles) {
		r := c.Roles[alias]
		if r == nil {
			p.add("role %s: null", alias)
			continue
		}
		r.alias = alias
		c.validateRole(&p, r)
	}
	for _, alias := range sortedKeys(c.Roles) {
		if r := c.Roles[alias]; r != nil {
			c.validateChain(&p, r)
		}
	}
	c.validateKeys(&p)
	return p
}

func checkEnv(p *problems, where, name string) {
	if !envRE.MatchString(name) {
		p.add("%s %q is not an environment name HNX_SECRET_[A-Z0-9_]+", where, name)
	}
}

func checkCount(p *problems, where string, v *int) {
	if v != nil && *v < 0 {
		p.add("%s: %d is negative", where, *v)
	}
}

func checkNumber(p *problems, where string, v *float64) {
	if v != nil && (math.IsNaN(*v) || math.IsInf(*v, 0) || *v < 0) {
		p.add("%s: must be a number >= 0", where)
	}
}

func (c *Config) validateRole(p *problems, r *Role) {
	w := "role " + r.alias
	if !slugRE.MatchString(r.alias) {
		p.add("%s: the alias is not a slug", w)
	}
	if r.Kind != "chat" && r.Kind != "embedding" {
		p.add("%s: kind %q is not chat or embedding", w, r.Kind)
	}
	if r.MaxContextTokens != nil && *r.MaxContextTokens <= 0 {
		p.add("%s: max_context_tokens must be positive or null", w)
	}
	var ok bool
	if r.ceiling, ok = ParseCanonical(r.TLPCeiling); !ok {
		p.add("%s: tlp_ceiling %q is not a canonical TLP label", w, r.TLPCeiling)
	} else if r.LeavesLab && !r.ceiling.AtOrBelow(Green) {
		// a role whose chain leaves the lab may carry at most green data out of it
		p.add("%s: the role leaves the lab, so its tlp_ceiling must be green or clear, not %s", w, r.TLPCeiling)
	}
	if len(r.Deployments) == 0 {
		p.add("%s: at least one deployment is required", w)
	}
	for i, d := range r.Deployments {
		if d == nil {
			p.add("%s: deployment %d is null", w, i+1)
			continue
		}
		validateDeployment(p, r, i, d)
	}
	if l := r.Limits; l != nil {
		if l.WindowS <= 0 {
			p.add("%s: limits.window_s must be > 0", w)
		}
		checkCount(p, w+": limits.max_requests", l.MaxRequests)
		checkCount(p, w+": limits.max_tokens", l.MaxTokens)
		checkNumber(p, w+": limits.max_cost", l.MaxCost)
		if l.MaxCost != nil && r.CostPer1KTokens == nil {
			p.add("%s: limits.max_cost needs cost_per_1k_tokens", w)
		}
	}
	checkNumber(p, w+": cost_per_1k_tokens", r.CostPer1KTokens)
}

func validateDeployment(p *problems, r *Role, i int, d *Deployment) {
	w := fmt.Sprintf("role %s deployment %d", r.alias, i+1)
	if want := r.alias + "-" + strconv.Itoa(i+1); d.ID != want {
		p.add("%s: id %q, expected %q", w, d.ID, want)
	}
	if strings.TrimSpace(d.Backend) == "" {
		p.add("%s: backend is empty", w)
	}
	if d.Locality != "local" && d.Locality != "cloud" {
		p.add("%s: locality %q is not local or cloud", w, d.Locality)
	}
	if d.Protocol != "openai" && d.Protocol != "anthropic" {
		p.add("%s: protocol %q is not openai or anthropic", w, d.Protocol)
	}
	if strings.TrimSpace(d.Model) == "" {
		p.add("%s: model is empty", w)
	}
	if d.APIKeyEnv != nil {
		checkEnv(p, w+": api_key_env", *d.APIKeyEnv)
	}
	if err := checkBaseURL(d.BaseURL); err != "" {
		p.add("%s: base_url %q %s", w, d.BaseURL, err)
	}
	if d.Protocol == "anthropic" && r.Kind == "embedding" {
		p.add("%s: an embedding role cannot be served by an anthropic deployment", w)
	}
	if d.Locality == "cloud" && !r.LeavesLab {
		p.add("%s: a cloud deployment on a role with leaves_lab false", w)
	}
}

func checkBaseURL(s string) string {
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return "is not a URL"
	case u.Scheme != "http" && u.Scheme != "https":
		return "must be http or https"
	case u.Host == "" || u.Hostname() == "":
		return "has no host"
	case u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(s, "?#"):
		return "must be scheme://host[:port] only"
	case u.Path != "":
		return "must have no path and no trailing slash"
	}
	return ""
}

func (c *Config) validateChain(p *problems, r *Role) {
	w := "role " + r.alias
	seen := map[string]bool{}
	for _, f := range r.Fallbacks {
		fr := c.Roles[f]
		switch {
		case f == r.alias:
			p.add("%s: fallbacks name the role itself", w)
		case seen[f]:
			p.add("%s: fallback %s is listed twice", w, f)
		case fr == nil:
			p.add("%s: fallback %s is not a role", w, f)
		case fr.Kind != r.Kind:
			p.add("%s: fallback %s is a %s role but role %s is a %s role: a fallback must be the same kind",
				w, f, fr.Kind, r.alias, r.Kind)
		case fr.LeavesLab && !r.LeavesLab:
			p.add("%s: fallback %s leaves the lab, so the role must have leaves_lab true", w, f)
		}
		seen[f] = true
	}
}

func (c *Config) validateKeys(p *problems) {
	aliases := map[string]bool{}
	envs := map[string]string{c.AdminKeyEnv: "admin_key_env"}
	if c.TelemetryReader != nil {
		claimEnv(p, envs, c.TelemetryReader.KeyEnv, "telemetry_reader")
	}
	for _, r := range c.Roles {
		for _, d := range nonNil(r) {
			if d.APIKeyEnv != nil {
				if who, ok := envs[*d.APIKeyEnv]; ok {
					p.add("deployment %s: api_key_env %s is also the env of %s", d.ID, *d.APIKeyEnv, who)
				}
			}
		}
	}
	prev := ""
	for i, k := range c.Keys {
		if k == nil {
			p.add("key %d is null", i+1)
			continue
		}
		w := "key " + k.Alias
		if !slugRE.MatchString(k.Alias) {
			p.add("%s: the alias is not a slug", w)
		}
		if aliases[k.Alias] {
			p.add("%s: the alias is declared twice", w)
		}
		if k.Alias < prev {
			p.add("%s: keys must be sorted by alias", w)
		}
		prev, aliases[k.Alias] = k.Alias, true
		checkEnv(p, w+": key_env", k.KeyEnv)
		claimEnv(p, envs, k.KeyEnv, w)
		for _, r := range c.Roles {
			for _, d := range nonNil(r) {
				if d.APIKeyEnv != nil && *d.APIKeyEnv == k.KeyEnv {
					p.add("%s: key_env %s is also deployment %s's api_key_env", w, k.KeyEnv, d.ID)
				}
			}
		}
		c.validateKey(p, w, k)
	}
}

func claimEnv(p *problems, envs map[string]string, env, who string) {
	if other, ok := envs[env]; ok {
		p.add("%s: env %s is already used by %s", who, env, other)
		return
	}
	envs[env] = who
}

func nonNil(r *Role) []*Deployment {
	if r == nil {
		return nil
	}
	out := make([]*Deployment, 0, len(r.Deployments))
	for _, d := range r.Deployments {
		if d != nil {
			out = append(out, d)
		}
	}
	return out
}

func (c *Config) validateKey(p *problems, w string, k *Key) {
	if k.Owner != k.Alias && !profileRE.MatchString(k.Owner) {
		p.add("%s: owner %q is neither profile:<id> nor the alias", w, k.Owner)
	}
	if k.DataTier != "local-only" && k.DataTier != "cloud-allowed" {
		p.add("%s: data_tier %q is not local-only or cloud-allowed", w, k.DataTier)
	}
	var ok bool
	if k.ceiling, ok = ParseCanonical(k.TLPCeiling); !ok {
		p.add("%s: tlp_ceiling %q is not a canonical TLP label", w, k.TLPCeiling)
	}
	if !sort.StringsAreSorted(k.Roles) {
		p.add("%s: roles must be sorted", w)
	}
	k.roleSet = map[string]bool{}
	for _, name := range k.Roles {
		r := c.Roles[name]
		switch {
		case k.roleSet[name]:
			p.add("%s: role %s is listed twice", w, name)
		case r == nil:
			p.add("%s: role %s is not in roles", w, name)
		case k.DataTier == "local-only" && (r.LeavesLab || hasCloud(r)):
			p.add("%s: a local-only key lists role %s, which leaves the lab", w, name)
		}
		k.roleSet[name] = true
	}
	for _, name := range k.Roles {
		if r := c.Roles[name]; r != nil {
			for _, f := range r.Fallbacks {
				if !k.roleSet[f] {
					p.add("%s: role %s falls back to %s, which the key does not list", w, name, f)
				}
			}
		}
	}
	if l := k.Limits; l != nil {
		if l.WindowS <= 0 {
			p.add("%s: limits.window_s must be > 0", w)
		}
		checkCount(p, w+": limits.max_requests", l.MaxRequests)
		checkCount(p, w+": limits.max_tokens", l.MaxTokens)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func hasCloud(r *Role) bool {
	for _, d := range nonNil(r) {
		if d.Locality == "cloud" {
			return true
		}
	}
	return false
}
