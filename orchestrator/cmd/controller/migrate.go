// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"

	"github.com/homelab-next/homelab-next/orchestrator/internal/config"
	"github.com/homelab-next/homelab-next/orchestrator/internal/grants"
	"github.com/homelab-next/homelab-next/orchestrator/internal/pathscope"
	"github.com/homelab-next/homelab-next/orchestrator/internal/profile"
)

// maxSiteFileBytes bounds every file migrate reads besides the configuration.
const maxSiteFileBytes = 64 << 10

// maxConfigBytes bounds the configuration migrate reads.
const maxConfigBytes = 1 << 20

// migrate is `controller migrate`: it rewrites a configuration in the private controller's keys
// into this controller's (config.MigrateWith) and, given --profile-aliases, the profiles it names
// (profile.MigrateDir, with the load options of the migrated configuration). It writes the new
// configuration to --out, a file that must not exist (owner-only), and never changes --config.
// Serving without a token is never inferred: an old configuration that leaves API authentication
// unset is refused unless --allow-unauthenticated-api says so.
func migrate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("controller migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "the configuration to migrate (required; left unchanged)")
	out := fs.String("out", "", "where the migrated configuration is written (required; must not exist)")
	siteRenames := fs.String("site-renames", "", "a file of the site's own old key names and their new keys")
	aliases := fs.String("profile-aliases", "", "a file of the site's old profile keys and their new keys: the profiles are migrated in place")
	scope := fs.String("scope", "", "a file holding the tree's zones (the scope block), for a configuration that has none")
	engine := fs.String("engine-metrics", "", "a file naming the engine's metrics (the engine_metrics block), for a configuration that has none")
	allowUnauth := fs.Bool("allow-unauthenticated-api", false,
		"accept an old configuration that leaves API authentication unset: the result serves without a token, on loopback only")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 || *cfgPath == "" || *out == "" {
		fmt.Fprintln(stderr, "controller migrate: --config and --out are required, and nothing else")
		return exitUsage
	}
	data, err := grants.ReadConfigFile(*cfgPath, maxConfigBytes)
	if err != nil {
		fmt.Fprintln(stderr, "controller migrate: the configuration:", err)
		return exitUsage
	}
	opts := config.MigrateOptions{AllowUnauthenticatedAPI: *allowUnauth}
	if *siteRenames != "" {
		if opts.ExtraRenames, err = config.LoadSiteRenames(*siteRenames); err != nil {
			fmt.Fprintln(stderr, "controller migrate: --site-renames:", err)
			return exitProblem
		}
	}
	if *scope != "" {
		z, err := loadScope(*scope)
		if err != nil {
			fmt.Fprintln(stderr, "controller migrate: --scope:", err)
			return exitProblem
		}
		opts.Scope = &z
	}
	if *engine != "" {
		m, err := config.LoadEngineMetrics(*engine)
		if err != nil {
			fmt.Fprintln(stderr, "controller migrate: --engine-metrics:", err)
			return exitProblem
		}
		opts.EngineMetrics = &m
	}
	migrated, notes, err := config.MigrateWith(data, opts)
	if err != nil {
		fmt.Fprintln(stderr, "controller migrate:", err)
		return exitProblem
	}
	cfg, err := config.Parse(migrated)
	if err != nil {
		fmt.Fprintln(stderr, "controller migrate: the migrated configuration does not load:", err)
		return exitProblem
	}
	absCfg, err := filepath.Abs(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "controller migrate:", err)
		return exitUsage
	}
	dir := filepath.Dir(absCfg)
	var keyAliases profile.KeyAliases
	if *aliases != "" {
		raw, err := grants.ReadConfigFile(*aliases, maxSiteFileBytes)
		if err == nil {
			keyAliases, err = profile.ParseKeyAliases(raw)
		}
		if err != nil {
			fmt.Fprintln(stderr, "controller migrate: --profile-aliases:", err)
			return exitProblem
		}
	}

	// The new configuration goes to a temporary file beside --out first, and is renamed into
	// place only once the profiles (when asked) have migrated: a failed run leaves neither.
	tmp, err := createExclusive(*out + ".tmp")
	if err != nil {
		fmt.Fprintln(stderr, "controller migrate: --out:", err)
		return exitProblem
	}
	committed := false
	defer func() {
		if !committed {
			os.Remove(tmp.Name())
		}
	}()
	_, err = tmp.Write(migrated)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		fmt.Fprintln(stderr, "controller migrate: write --out:", err)
		return exitProblem
	}
	if keyAliases != nil {
		popts, _, err := cfg.ProfileLoadOptions(dir)
		if err != nil {
			fmt.Fprintln(stderr, "controller migrate: the migrated configuration's profile options:", err)
			return exitProblem
		}
		popts.KeyAliases = keyAliases
		profilesDir := cfg.ProfilesDir
		if !filepath.IsAbs(profilesDir) {
			profilesDir = filepath.Join(dir, profilesDir)
		}
		pnotes, err := profile.MigrateDir(profilesDir, popts)
		if err != nil {
			fmt.Fprintln(stderr, "controller migrate: the profiles:", err)
			return exitProblem
		}
		notes = append(notes, pnotes...)
	}
	if err := os.Link(tmp.Name(), *out); err != nil {
		fmt.Fprintln(stderr, "controller migrate: --out:", err)
		return exitProblem
	}
	committed = true
	os.Remove(tmp.Name())
	for _, n := range notes {
		fmt.Fprintln(stderr, "note:", n)
	}
	fmt.Fprintf(stdout, "migrated configuration written to %s (%d notes)\n", *out, len(notes))
	return exitOK
}

// createExclusive creates path, owner-only, failing when anything is there.
func createExclusive(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

// loadScope reads a site's zones file: one YAML mapping with the scope block's keys, decoded
// strictly and validated (pathscope.NewZones).
func loadScope(path string) (pathscope.Zones, error) {
	raw, err := grants.ReadConfigFile(path, maxSiteFileBytes)
	if err != nil {
		return pathscope.Zones{}, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var z pathscope.Zones
	if err := dec.Decode(&z); err != nil {
		return pathscope.Zones{}, fmt.Errorf("not a zones mapping: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return pathscope.Zones{}, errors.New("holds more than one YAML document")
	}
	return pathscope.NewZones(z)
}
