// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/backends"
	"github.com/homelab-next/homelab-next/orchestrator/internal/config"
	"github.com/homelab-next/homelab-next/orchestrator/internal/grants"
	"github.com/homelab-next/homelab-next/orchestrator/internal/inference"
	"github.com/homelab-next/homelab-next/orchestrator/internal/lessons"
	"github.com/homelab-next/homelab-next/orchestrator/internal/profile"
	"github.com/homelab-next/homelab-next/orchestrator/internal/prompt"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	execrunner "github.com/homelab-next/homelab-next/orchestrator/internal/runner/exec"
)

// site is a configuration and everything loaded from the files it names: what check judges and
// serve runs. Loading it opens no database, binds no port, reaches no network and reads no secret
// file's contents.
type site struct {
	cfg      config.Config
	dir      string // the configuration's directory: relative paths in it are read from here
	opts     profile.LoadOptions
	profiles *profile.Registry
	catalog  *grants.Catalog
	lessons  *lessons.Index
	// contracts are the dispatch prompt's contracts, loaded once (Config.PromptContractTexts).
	contracts []string
	runner    runner.Runner
	notes     []string
}

// path is p read relative to the configuration's directory; "" stays "".
func (s *site) path(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(s.dir, p)
}

// errUnreadable marks a file that cannot be read at all: exit 2 rather than 1.
var errUnreadable = errors.New("unreadable")

// loadSite reads the configuration at path and every file it names, and returns each problem
// found, one per entry. A problem that stops the rest (the configuration itself) is the only one.
func loadSite(path string) (*site, []error) {
	if path == "" {
		return nil, []error{fmt.Errorf("%w: --config is required", errUnreadable)}
	}
	if _, err := os.Stat(path); err != nil {
		return nil, []error{fmt.Errorf("%w: the configuration file: %v", errUnreadable, errors.Unwrap(err))}
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, []error{fmt.Errorf("config: %w", err)}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, []error{fmt.Errorf("%w: %v", errUnreadable, err)}
	}
	s := &site{cfg: cfg, dir: filepath.Dir(abs), notes: cfg.Notices}
	var problems []error

	opts, opaque, err := cfg.ProfileLoadOptions(s.dir)
	if err != nil {
		problems = append(problems, fmt.Errorf("profiles: %w", err))
	} else {
		s.opts = opts
		for _, k := range opaque {
			s.notes = append(s.notes, "profile extension "+k+" is carried opaque (unchecked)")
		}
		if cfg.ProfilesDir == "" {
			problems = append(problems, errors.New("config: profiles_dir is required"))
		} else if reg, err := profile.LoadRegistry(s.path(cfg.ProfilesDir), opts); err != nil {
			problems = append(problems, fmt.Errorf("profiles: %w", err))
		} else {
			s.profiles = reg
			s.notes = append(s.notes, reg.Notices()...)
		}
	}
	if cfg.GrantsCatalog != "" {
		if cat, err := grants.LoadCatalog(s.path(cfg.GrantsCatalog), cfg.Zones()); err != nil {
			problems = append(problems, fmt.Errorf("grants catalog: %w", err))
		} else {
			s.catalog = cat
		}
	}
	if s.profiles != nil && (cfg.GrantsCatalog == "" || s.catalog != nil) {
		if err := s.profiles.CheckGrants(s.catalog); err != nil {
			problems = append(problems, joined("grants", err)...)
		}
	}
	if lp, rp, err := cfg.Registers(); err != nil {
		problems = append(problems, fmt.Errorf("config: %w", err))
	} else if lp != "" {
		if ix, err := lessons.LoadConfigured(s.path(lp), s.path(rp)); err != nil {
			problems = append(problems, fmt.Errorf("registers: %w", err))
		} else {
			s.lessons = ix
		}
	}
	if c, err := cfg.PromptContractTexts(s.dir, prompt.DefaultContracts()); err != nil {
		problems = append(problems, fmt.Errorf("prompt contracts: %w", err))
	} else {
		s.contracts = c
	}
	if cfg.APIAuth.On() {
		if err := checkSecretFile(s.path(cfg.APIAuth.TokensFile)); err != nil {
			problems = append(problems, fmt.Errorf("api_auth.tokens_file: %w", err))
		}
	}
	if cfg.LockPath != "" && anyInterlock(cfg.Backends) {
		if err := checkLockDir(cfg.LockPath); err != nil {
			problems = append(problems, fmt.Errorf("lock_path: %w", err))
		}
	}
	if r, err := buildRunner(cfg.Runner); err != nil {
		problems = append(problems, fmt.Errorf("runner: %w", err))
	} else if r == nil {
		s.notes = append(s.notes, "runner.kind is not set: this configuration loads but cannot serve")
	} else {
		s.runner = r
	}
	// The pool's own settings, checked as serve checks them, with no runner started and no store.
	if s.runner != nil {
		if _, err := buildPool(cfg, s.runner, nil, nil); err != nil {
			problems = append(problems, fmt.Errorf("backends: %w", err))
		}
	}
	return s, problems
}

// joined splits an errors.Join into one problem per error.
func joined(prefix string, err error) []error {
	var out []error
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range j.Unwrap() {
			out = append(out, fmt.Errorf("%s: %w", prefix, e))
		}
		return out
	}
	return []error{fmt.Errorf("%s: %w", prefix, err)}
}

// checkSecretFile checks a secret file without reading it: set, a regular file (no link), and one
// this process may open for reading.
func checkSecretFile(path string) error {
	if path == "" {
		return errors.New("not set")
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("cannot be read: %v", errors.Unwrap(err))
	}
	if !fi.Mode().IsRegular() {
		return errors.New("is not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot be opened: %v", errors.Unwrap(err))
	}
	return f.Close()
}

// anyInterlock reports whether a backend the pool dispatches to serialises through lock_path.
func anyInterlock(b config.Backends) bool {
	local, _ := backends.FromConfig(b)
	for _, l := range local {
		if l.NeedsInterlock {
			return true
		}
	}
	return false
}

// checkLockDir refuses the interlock's directory when it is missing or anyone but its owner may
// write it: the interlock refuses a lock file there, and every local attempt on an interlocked
// backend would then fail unclassified, so the controller refuses to start instead.
func checkLockDir(lockPath string) error {
	dir := filepath.Dir(lockPath)
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("its directory cannot be read: %v", errors.Unwrap(err))
	}
	if !fi.IsDir() {
		return errors.New("its directory is not a directory")
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("its directory is writable by group or others (mode %04o): keep the lock file in the service's own runtime directory", fi.Mode().Perm())
	}
	return nil
}

// buildRunner is the configured runner; nil with no kind.
func buildRunner(r config.Runner) (runner.Runner, error) {
	switch r.Kind {
	case "":
		return nil, nil
	case config.RunnerKindExec:
		classes := map[int]runner.Class{}
		for code, name := range r.Exec.ExitClasses {
			c, ok := runner.ParseClass(name)
			if !ok {
				return nil, fmt.Errorf("exec.exit_classes: exit status %d names no runner class", code)
			}
			classes[code] = c
		}
		return execrunner.New(execrunner.Config{
			Argv: r.Exec.Argv, UsageArgs: r.Exec.UsageArgs, ToolsetsArgs: r.Exec.ToolsetsArgs,
			ExitClasses: classes, EnvAllowlist: r.EnvAllowlist, RunDirBase: r.RunDirBase,
			MaxResponseBytes: r.Exec.MaxResponseBytes, KillGrace: time.Duration(r.Exec.KillGraceSeconds) * time.Second,
		})
	}
	return nil, fmt.Errorf("kind %q is not built in", r.Kind)
}

// promptStats is the store's last-call prompt statistics, for token-weighted admission.
type promptStats interface {
	AgentLastCallPromptP90(agentKey string, limit int) (p90 int, n int, err error)
}

// buildPool is the backend pool the configuration describes, validated. drains and stats are the
// store (nil for a check).
func buildPool(cfg config.Config, r runner.Runner, drains backends.DrainStore, stats promptStats) (*backends.Policy, error) {
	local, cloud := backends.FromConfig(cfg.Backends)
	load, kv := backends.MetricsFromConfig(cfg.EngineMetrics)
	p := &backends.Policy{
		Runner:                 r,
		Backends:               local,
		CloudHome:              cloud,
		InterlockWait:          time.Duration(cfg.InterlockWaitTimeoutSeconds) * time.Second,
		Limits:                 backends.LimitsFromConfig(cfg.Runner),
		JobLimit:               backends.JobLimitFromConfig(cfg.Runner),
		PrimaryFirst:           cfg.PrimaryFirst,
		LoadMetrics:            load,
		KV:                     kv,
		TokenWeightedAdmission: cfg.TokenWeightedAdmission,
		KVBudgetFraction:       cfg.KVBudgetFraction,
		DrainStore:             drains,
	}
	if cfg.LockPath != "" {
		p.Interlock = inference.NewInterlock(cfg.LockPath, 0)
	}
	if stats != nil {
		p.AgentPromptP90 = func(agent string) (int, int) {
			p90, n, err := stats.AgentLastCallPromptP90(agent, 200)
			if err != nil {
				return 0, 0
			}
			return p90, n
		}
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// isUnreadable reports whether a problem is a file that cannot be read at all.
func isUnreadable(err error) bool {
	return errors.Is(err, errUnreadable) || errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission)
}
