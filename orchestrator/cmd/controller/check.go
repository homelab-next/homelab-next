// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/homelab-next/homelab-next/orchestrator/internal/backends"
	"github.com/homelab-next/homelab-next/orchestrator/internal/config"
	"github.com/homelab-next/homelab-next/orchestrator/internal/profile"
)

// check is `controller check --config FILE` (ADR-0026 decision 17): the Go loader's judgement of a
// site's configuration, every profile it names and their grants, without opening the database,
// binding a port or reaching the network. A secret file (the tokens file) is checked to be a
// regular file this process may read; its contents are never read. Exit 0 clean, 1 one line per
// problem, 2 a usage error or an unreadable file.
func check(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("controller check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "the controller's configuration (required)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "controller check: unexpected arguments")
		return exitUsage
	}
	s, problems := loadSite(*cfgPath)
	if s != nil && s.profiles != nil {
		problems = append(problems, unsatisfiable(s.cfg, s.profiles.All())...)
	}
	if s != nil {
		for _, n := range s.notes {
			fmt.Fprintln(stderr, "note:", n)
		}
	}
	if len(problems) == 0 {
		fmt.Fprintf(stdout, "controller config ok: %d profiles\n", len(s.profiles.All()))
		return exitOK
	}
	code := exitProblem
	for _, p := range problems {
		fmt.Fprintln(stdout, oneLine(p.Error()))
		if isUnreadable(p) {
			code = exitUsage
		}
	}
	return code
}

// oneLine keeps a problem on one line, so each line of the output is one problem.
func oneLine(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' {
			r = ' '
		}
		if r < 0x20 && r != '\t' {
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

// unsatisfiable is one problem per profile whose backend_affinity no configured local backend
// meets and that has no cloud leg to run on instead (local_only, or no backends.cloud): such a
// job is refused with no local capacity at every attempt, so it would never run. The check says
// so before a deploy rather than at the first submit (a window is raised on the backend, with its
// role's max_context_tokens, never by declaring one the engine does not serve). Exclusive alone
// narrows nothing.
func unsatisfiable(cfg config.Config, profiles []*profile.Profile) []error {
	local, cloudHome := backends.FromConfig(cfg.Backends)
	pool := &backends.Policy{Backends: local}
	var out []error
	for _, p := range profiles {
		a := backends.AffinityOf(p.BackendAffinity)
		if a.IsZero() || (!p.LocalOnly && cloudHome != "") {
			continue
		}
		met := false
		windows := make([]string, 0, len(local))
		for _, b := range local {
			if _, ok, _ := pool.ExplainEligibility(b.Name, a); ok {
				met = true
				break
			}
			windows = append(windows, fmt.Sprintf("%s max_context %d", b.Name, b.MaxContext))
		}
		if met {
			continue
		}
		var asked []string
		if a.MinContext > 0 {
			asked = append(asked, fmt.Sprintf("min_context %d", a.MinContext))
		}
		if len(a.RequireTags) > 0 {
			asked = append(asked, fmt.Sprintf("require_tags %v", a.RequireTags))
		}
		if len(a.ExcludeBackends) > 0 {
			asked = append(asked, fmt.Sprintf("exclude_backends %v", a.ExcludeBackends))
		}
		why := "no cloud leg is configured (backends.cloud)"
		if p.LocalOnly {
			why = "it is local_only"
		}
		out = append(out, fmt.Errorf("profile %s: backend_affinity (%s) is met by no local backend (%s) and %s: no cloud leg, so it would never run",
			p.AgentKey, strings.Join(asked, ", "), strings.Join(windows, "; "), why))
	}
	return out
}
