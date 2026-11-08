// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"slices"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/config"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
)

// FromConfig is the pool's local backends and cloud home from a configuration's backends block:
// the local backend, then the local fallback, then each additional backend, in that order, each
// only when it has a home (a backend without one is not dispatched to).
//
// A backend's interlock is config.Backend.InterlockRequired: unset is on. The private controller
// this one replaces built its local backend with the interlock off whatever its file said;
// config.Migrate writes that as needs_interlock: false into a migrated file, so here every
// backend reads its own key and none is special.
//
// The cloud backend gives its home only. The cloud leg never holds the interlock, and its endpoint
// and probes are never put on a session: progress liveness does not watch the cloud leg's sockets,
// and the pool neither probes its health nor counts its load.
func FromConfig(b config.Backends) (local []Backend, cloudHome string) {
	add := func(c config.Backend) {
		if c.Home == "" {
			return
		}
		local = append(local, Backend{
			Name:           c.Name,
			Home:           c.Home,
			NeedsInterlock: c.InterlockRequired(),
			Weight:         c.Weight,
			Tags:           slices.Clone(c.Tags),
			MaxContext:     c.MaxContext,
			MaxConcurrent:  c.MaxConcurrent,
			LoadProbeURLs:  slices.Clone(c.LoadProbeURLs),
			HealthURL:      c.HealthURL,
			Endpoint:       c.Endpoint,
		})
	}
	add(b.Local)
	add(b.LocalFallback)
	for _, a := range b.Additional {
		add(a)
	}
	return local, b.Cloud.Home
}

// LimitsFromConfig are every attempt's limits from the runner block.
func LimitsFromConfig(r config.Runner) runner.Limits {
	return runner.Limits{
		Timeout:      time.Duration(r.TimeoutSeconds) * time.Second,
		StallTimeout: time.Duration(r.StallTimeoutSeconds) * time.Second,
		MaxTurns:     r.MaxTurns,
		Liveness:     r.Liveness,
	}
}

// JobLimitFromConfig is the job's bound on its whole chain: runner.job_timeout_seconds when set,
// else twice runner.timeout_seconds (room for one more backend or the cloud leg after a full
// attempt), else none.
func JobLimitFromConfig(r config.Runner) time.Duration {
	if r.JobTimeoutSeconds > 0 {
		return time.Duration(r.JobTimeoutSeconds) * time.Second
	}
	if r.TimeoutSeconds > 0 {
		return 2 * time.Duration(r.TimeoutSeconds) * time.Second
	}
	return 0
}
