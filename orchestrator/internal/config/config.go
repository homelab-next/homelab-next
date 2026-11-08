// SPDX-License-Identifier: Apache-2.0

// Package config loads the controller's configuration: one YAML file, decoded strictly (an
// unknown key at any level is refused), with keys that name no product. A configuration written
// for the private controller this one replaces loads too, its old keys mapped to the new ones
// (Load notes each), until Migrate rewrites it; one that sets both an old key and its new key is
// refused, and so is one that sets a key of what was not ported (the HTTP passthrough). The table
// of old and new keys is docs/orchestration-controller.md, "The controller's configuration".
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/homelab-next/homelab-next/orchestrator/internal/gatewaytag"
	"github.com/homelab-next/homelab-next/orchestrator/internal/pathscope"
	"github.com/homelab-next/homelab-next/orchestrator/internal/profile"
)

// Backend is one inference backend of the pool. The controller never calls a backend's API
// itself: a runner session does, through the gateway its home configures. What the controller
// keeps of a backend is its name, how much it may carry and how to probe it.
type Backend struct {
	Name string `yaml:"name"`
	// Home is the runner's configuration reference for sessions on this backend (opaque to the
	// controller: the runner reads it). A backend without one is not dispatched to.
	Home string `yaml:"home"`
	// Endpoint is host:port of the backend's model server, which the runner's progress liveness
	// watches for socket traffic. A probe only: nothing is sent to it.
	Endpoint string `yaml:"endpoint"`
	// Weight is the backend's relative capacity for weighted selection; 0 or less counts as 1.
	Weight int `yaml:"weight"`
	// Tags are capability labels a profile's backend_affinity.require_tags matches. Declarative:
	// nothing checks them against the model the backend serves.
	Tags []string `yaml:"tags"`
	// MaxContext is the backend's usable context window in tokens; 0 is unknown, and a profile's
	// min_context never matches an unknown window.
	MaxContext int `yaml:"max_context"`
	// MaxConcurrent is the backend's measured concurrent-request ceiling; 0 is unmeasured (never
	// penalised by load-based selection).
	MaxConcurrent int `yaml:"max_concurrent"`
	// LoadProbeURLs are metrics endpoints read for the backend's running and waiting requests;
	// empty: the controller's own in-flight count. Probes only.
	LoadProbeURLs []string `yaml:"load_probe_urls"`
	// HealthURL is probed with GET; a non-2xx or unreachable answer marks the backend down. Empty:
	// never marked down. A probe only.
	HealthURL string `yaml:"health_url"`
	// NeedsInterlock: calls to this backend serialise through the shared lock file (lock_path).
	// Unset is true; use InterlockRequired.
	NeedsInterlock *bool `yaml:"needs_interlock"`
}

// InterlockRequired resolves NeedsInterlock's default: unset means true.
func (b Backend) InterlockRequired() bool { return b.NeedsInterlock == nil || *b.NeedsInterlock }

// Backends is the pool: a local backend, an optional second local one tried after it, further
// local backends, and the cloud backend a job that is not local-only falls back to.
type Backends struct {
	Local         Backend   `yaml:"local"`
	LocalFallback Backend   `yaml:"local_fallback"`
	Cloud         Backend   `yaml:"cloud"`
	Additional    []Backend `yaml:"additional"`
}

// Runner holds the limits the controller puts on every runner session.
type Runner struct {
	// TimeoutSeconds bounds one attempt.
	TimeoutSeconds int `yaml:"timeout_seconds"`
	// JobTimeoutSeconds bounds one job's whole attempt chain (every backend tried, the cloud
	// fallback included); 0 is twice TimeoutSeconds.
	JobTimeoutSeconds int `yaml:"job_timeout_seconds"`
	// StallTimeoutSeconds ends a session that shows no progress for this long; 0 disables it.
	StallTimeoutSeconds int `yaml:"stall_timeout_seconds"`
	// StallPollIntervalSeconds is how often progress is sampled; 0 is the runner's default.
	StallPollIntervalSeconds int `yaml:"stall_poll_interval_seconds"`
	// Liveness is what counts as progress: "" or "cpu" (CPU time of the session's process tree),
	// or "progress" (socket traffic to the backend's endpoint, or the backend's token progress).
	Liveness string `yaml:"liveness"`
	// MaxTurns caps the model turns of one session; 0 is no cap.
	MaxTurns int `yaml:"max_turns"`
	// RunDirBase: each session gets a fresh owner-only working directory under it. Empty: the
	// controller's own.
	RunDirBase string `yaml:"run_dir_base"`
	// EnvAllowlist: a session gets only these environment variables (an exact name, or a prefix
	// ending in "*"). Empty: the controller's whole environment.
	EnvAllowlist []string `yaml:"env_allowlist"`
	// JobHomeRoot is where a runner keeps per-job homes; empty is beside db_path.
	JobHomeRoot string `yaml:"job_home_root"`
}

// Liveness values.
var livenessModes = map[string]bool{"": true, "cpu": true, "progress": true}

// Events configures the job lifecycle event sender (package events).
type Events struct {
	// ForwarderURL receives each CloudEvents envelope as a POST (the forwarder contract). Empty
	// disables events.
	ForwarderURL string `yaml:"forwarder_url"`
	// Source is the envelope source, a svc: logical id. Empty: events.DefaultSource.
	Source string `yaml:"source"`
	// TokenEnv names an environment variable holding a bearer token for the forwarder.
	TokenEnv string `yaml:"token_env"`
	// QueueSize bounds the durable outbox (undelivered events); 0 is the sender's default.
	QueueSize int `yaml:"queue_size"`
	// GatewayTagPrefix prefixes the run id in the gateway tag every model request of a job
	// carries. Empty: the bare run id.
	GatewayTagPrefix string `yaml:"gateway_tag_prefix"`
}

// APIAuth configures bearer-token authentication of the HTTP API. It is on unless the file says
// enabled: false (Enabled nil is on: a safe default never rests on a key someone forgot).
type APIAuth struct {
	// Enabled: nil or true turns auth on, and TokensFile must then load or the controller refuses
	// to start; false serves the API with no token, on a loopback address only (package api).
	Enabled *bool `yaml:"enabled"`
	// TokensFile lists {caller, sha256, scopes}: each caller's token digest, never the token.
	TokensFile string `yaml:"tokens_file"`
}

// scopeKeys are the keys a scope block must set, each present even when empty, so a missing key
// is never read as "nothing denied" or "no findings root".
var scopeKeys = []string{"denied_roots", "findings_root", "shared_write", "reserved_names"}

// Config is the controller's configuration.
type Config struct {
	DBPath   string   `yaml:"db_path"`
	HTTPAddr string   `yaml:"http_addr"`
	LockPath string   `yaml:"lock_path"`
	Backends Backends `yaml:"backends"`
	Runner   Runner   `yaml:"runner"`
	// InterlockWaitTimeoutSeconds bounds how long a NeedsInterlock call waits for the lock before
	// it falls over to the next backend; 0 waits without bound.
	InterlockWaitTimeoutSeconds int `yaml:"interlock_wait_timeout_seconds"`
	// GrantsCatalog is the MCP server catalog of kinds (package grants; `hnx mcp catalog render
	// --client orchestrator`). Empty: no profile may declare grants.
	GrantsCatalog string `yaml:"grants_catalog"`
	// TokenWeightedAdmission admits queued jobs against a KV-token budget as well as the slot
	// cap. Off by default.
	TokenWeightedAdmission bool `yaml:"token_weighted_admission"`
	// KVBudgetFraction of the KV pool reservations may fill; 0 is 0.8.
	KVBudgetFraction float64 `yaml:"kv_budget_fraction"`
	// PrimaryFirst tries backends in configured order instead of weighted round-robin.
	PrimaryFirst bool `yaml:"primary_first"`
	// EngineMetrics names the metrics load_probe_urls serve (no default: the engine's own names,
	// which a site writes).
	EngineMetrics EngineMetrics `yaml:"engine_metrics"`
	// OrphanGraceSeconds: how long a job may have no live executor before the orphan sweep ends
	// it; 0 is 600, negative disables the sweep.
	OrphanGraceSeconds int `yaml:"orphan_grace_seconds"`
	// BackendHealthIntervalSeconds: how often health_url is probed; 0 is 15.
	BackendHealthIntervalSeconds int `yaml:"backend_health_interval_seconds"`
	// ProfilesDir is the profiles' directory (required).
	ProfilesDir string `yaml:"profiles_dir"`
	// ProfileExtensions are the deployment's own top-level profile keys; each needs an entry in
	// ProfileExtensionSchemas: a schema (inline, or the path of a JSON or YAML file relative to
	// the config's directory) or the string "opaque" to carry it unchecked.
	ProfileExtensions       []string             `yaml:"profile_extensions"`
	ProfileExtensionSchemas map[string]yaml.Node `yaml:"profile_extension_schemas"`
	// CursorFileTemplate is the one path shape a profile's prompt_context.cursor_file may take;
	// only profile.DefaultCursorTemplate is accepted for now.
	CursorFileTemplate string `yaml:"cursor_file_template"`
	// PromptDir is the one directory profiles' prompt text files are read from; relative to the
	// config's directory when not absolute. Empty: profiles may name no such file.
	PromptDir string `yaml:"prompt_dir"`
	// PromptStateFiles are the absolute state files a profile's prompt_context may name.
	PromptStateFiles []string `yaml:"prompt_state_files"`
	// FactsCommands is the catalog of facts commands, by name (profile.FactsCommand).
	FactsCommands map[string]profile.FactsCommand `yaml:"facts_commands"`
	// TreeRoot is the shared tree's root; when set, a job that ends cleanly but wrote nothing
	// under its profile's findings prefix is marked failed. Empty disables the check.
	TreeRoot string `yaml:"tree_root"`
	// BackendStatusCommand is run (argv, no shell) for GET /admin/backend-status, its stdout
	// returned as is. Empty: the route answers 501.
	BackendStatusCommand []string `yaml:"backend_status_command"`
	// LessonsPath and RunbooksPath are the lessons and runbooks registers (record directories,
	// package lessons). lessons_path is required unless lessons_disabled; runbooks_path needs it.
	LessonsPath     string `yaml:"lessons_path"`
	RunbooksPath    string `yaml:"runbooks_path"`
	LessonsDisabled bool   `yaml:"lessons_disabled"`
	// PromptContracts replace the built-in contracts every dispatch prompt carries (package
	// prompt's DefaultContracts) with these files' texts, in order. Unset: the built-in ones.
	// An explicit empty list is none: the site's opt-out, for a runner with no output tool to name
	// (a conformance stand-in, say). PromptContractsAppend adds files after them (the built-in
	// ones or the replacement).
	PromptContracts       []string `yaml:"prompt_contracts"`
	PromptContractsAppend []string `yaml:"prompt_contracts_append"`
	APIAuth               APIAuth  `yaml:"api_auth"`
	// APIPprof serves the profiling routes (/debug/pprof/*) behind the admin scope; the API
	// refuses it with authentication off.
	APIPprof bool `yaml:"api_pprof"`
	// APIMaxUnfinishedPerCaller bounds one submitter's unfinished jobs (a submit past it is a
	// 429); 0 is the API's default (1000).
	APIMaxUnfinishedPerCaller int `yaml:"api_max_unfinished_per_caller"`
	Events                Events   `yaml:"events"`
	// Scope is the shared tree's zones (pathscope.Zones). Required, every key present.
	Scope pathscope.Zones `yaml:"scope"`

	// Notices are what loading noted: each old key read under its new name.
	Notices []string `yaml:"-"`

	zones pathscope.Zones // Scope, validated
}

// On reports whether the API authenticates: unless enabled is set false.
func (a APIAuth) On() bool { return a.Enabled == nil || *a.Enabled }

// Zones are the validated scope zones.
func (c Config) Zones() pathscope.Zones { return c.zones }

// Load reads and checks the configuration at path (Parse).
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes a configuration strictly and checks it. Old keys are read under their new names
// (each noted in Notices); a key set under both names, a key of what was not ported or a repeated
// key is refused.
func Parse(data []byte) (Config, error) { return ParseWith(data, ParseOptions{}) }

// ParseOptions tune ParseWith.
type ParseOptions struct {
	// ExtraRenames are the site's own old key names (SiteRenames), read under their new names and
	// noted as Renames are.
	ExtraRenames SiteRenames
}

// ParseWith is Parse with a site's own renames.
func ParseWith(data []byte, opts ParseOptions) (Config, error) {
	extra, err := opts.ExtraRenames.renames()
	if err != nil {
		return Config{}, err
	}
	doc, err := parseNode(data)
	if err != nil {
		return Config{}, err
	}
	notes, _, err := migrateNode(doc, false, extra)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	raw, err := yaml.Marshal(doc)
	if err != nil {
		return Config{}, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("parse: %w", err)
	}
	cfg.Notices = notes
	if err := checkScopePresent(doc); err != nil {
		return Config{}, err
	}
	if cfg.zones, err = pathscope.NewZones(cfg.Scope); err != nil {
		return Config{}, fmt.Errorf("scope: %w", err)
	}
	cfg.Scope = cfg.zones
	if err := cfg.check(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// parseNode parses data into one mapping document, refusing a repeated key anywhere (a reader
// would see one of the two values, a migration the other).
func parseNode(data []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("parse: the configuration must be one mapping")
	}
	if err := noRepeatedKeys(doc.Content[0], ""); err != nil {
		return nil, err
	}
	if err := noAliases(doc.Content[0]); err != nil {
		return nil, err
	}
	return &doc, nil
}

func noRepeatedKeys(n *yaml.Node, at string) error {
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if seen[k] {
				return fmt.Errorf("parse: %s%s appears twice", at, k)
			}
			seen[k] = true
		}
	}
	for i, c := range n.Content {
		next := at
		if n.Kind == yaml.MappingNode && i%2 == 1 {
			next = at + n.Content[i-1].Value + "."
		}
		if err := noRepeatedKeys(c, next); err != nil {
			return err
		}
	}
	return nil
}

// noAliases refuses anchors, aliases and merge keys: a migration moves keys by name, and one
// reached through an alias would be moved in one place and left in the other.
func noAliases(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("parse: YAML anchors and aliases are not allowed in the configuration")
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if k := n.Content[i]; k.Kind != yaml.ScalarNode || k.ShortTag() == "!!merge" || k.Value == "<<" {
				return fmt.Errorf("parse: a configuration key must be a plain scalar (no merge key)")
			}
		}
	}
	for _, c := range n.Content {
		if err := noAliases(c); err != nil {
			return err
		}
	}
	return nil
}

// checkScopePresent refuses a configuration without a scope block or with one that leaves out a
// key: an absent key would read as its empty value, and an empty value there is a decision.
func checkScopePresent(doc *yaml.Node) error {
	scope := lookup(doc.Content[0], "scope")
	if scope == nil || scope.Kind != yaml.MappingNode {
		return fmt.Errorf("scope: required (the shared tree's zones: %s; see pathscope.Zones)", strings.Join(scopeKeys, ", "))
	}
	var missing []string
	for _, k := range scopeKeys {
		if lookup(scope, k) == nil {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("scope: %s must be set (an empty value is written out, never implied)", strings.Join(missing, ", "))
	}
	return nil
}

// check holds the decoded configuration to the rules decoding cannot state.
func (c Config) check() error {
	if c.APIPprof && !c.APIAuth.On() {
		return errors.New("api_pprof: profiling needs authentication on (it would open the process's profiles to every local user)")
	}
	if c.APIMaxUnfinishedPerCaller < 0 {
		return fmt.Errorf("api_max_unfinished_per_caller %d is negative", c.APIMaxUnfinishedPerCaller)
	}
	if c.APIAuth.On() && strings.TrimSpace(c.APIAuth.TokensFile) == "" {
		return errors.New("api_auth: authentication is on (the default) and no api_auth.tokens_file is given: name the tokens file, or set api_auth.enabled: false to serve without a token on a loopback address")
	}
	if !livenessModes[c.Runner.Liveness] {
		return fmt.Errorf("runner.liveness %q: want cpu or progress", c.Runner.Liveness)
	}
	for _, v := range []struct {
		key string
		n   int
	}{
		{"runner.timeout_seconds", c.Runner.TimeoutSeconds}, {"runner.job_timeout_seconds", c.Runner.JobTimeoutSeconds},
		{"runner.stall_timeout_seconds", c.Runner.StallTimeoutSeconds}, {"runner.stall_poll_interval_seconds", c.Runner.StallPollIntervalSeconds},
		{"runner.max_turns", c.Runner.MaxTurns}, {"interlock_wait_timeout_seconds", c.InterlockWaitTimeoutSeconds},
		{"backend_health_interval_seconds", c.BackendHealthIntervalSeconds},
	} {
		if v.n < 0 {
			return fmt.Errorf("%s %d is negative", v.key, v.n)
		}
	}
	if err := c.EngineMetrics.Check(); err != nil {
		return err
	}
	if c.KVBudgetFraction < 0 || c.KVBudgetFraction > 1 {
		return fmt.Errorf("kv_budget_fraction %v: want 0 (the default) to 1", c.KVBudgetFraction)
	}
	if c.LockPath != "" && (!filepath.IsAbs(c.LockPath) || filepath.Clean(c.LockPath) != c.LockPath) {
		return fmt.Errorf("lock_path %q: want a clean absolute path (every caller of the backend must name the same file)", c.LockPath)
	}
	if !gatewaytag.ValidPrefix(c.Events.GatewayTagPrefix) {
		return fmt.Errorf("events.gateway_tag_prefix %q: want at most 64 of [A-Za-z0-9._:/-]", c.Events.GatewayTagPrefix)
	}
	backends := []struct {
		at string
		b  Backend
	}{{"backends.local", c.Backends.Local}, {"backends.local_fallback", c.Backends.LocalFallback}, {"backends.cloud", c.Backends.Cloud}} // scrub-allow: config key paths, not host names
	for i, b := range c.Backends.Additional {
		backends = append(backends, struct {
			at string
			b  Backend
		}{fmt.Sprintf("backends.additional[%d]", i), b})
	}
	for _, e := range backends {
		if e.b.Endpoint != "" {
			if _, _, err := net.SplitHostPort(e.b.Endpoint); err != nil || strings.Contains(e.b.Endpoint, "/") {
				return fmt.Errorf("%s.endpoint %q: want host:port", e.at, e.b.Endpoint)
			}
		}
	}
	if cmd := c.BackendStatusCommand; len(cmd) > 0 && !filepath.IsAbs(cmd[0]) && strings.ContainsRune(cmd[0], '/') {
		return fmt.Errorf("backend_status_command[0] %q must be an absolute path or a bare program name", cmd[0])
	}
	return nil
}

// PromptContractTexts returns the contracts every dispatch prompt carries: defaults (the built-in
// ones, prompt.DefaultContracts, which the caller passes so this package does not import the
// prompt builder) unless prompt_contracts replaces them, then prompt_contracts_append's files.
// Files are read relative to configDir unless absolute, one trailing newline dropped each. The
// result is never nil, so prompt.Input.Contracts takes it as it is; it is empty when the site
// opted out (prompt_contracts: [] and nothing appended).
func (c Config) PromptContractTexts(configDir string, defaults []string) ([]string, error) {
	read := func(key string, names []string) ([]string, error) {
		out := make([]string, 0, len(names))
		for _, name := range names {
			path := name
			if !filepath.IsAbs(path) {
				path = filepath.Join(configDir, path)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			out = append(out, strings.TrimSuffix(string(data), "\n"))
		}
		return out, nil
	}
	out := append([]string{}, defaults...)
	if c.PromptContracts != nil {
		var err error
		if out, err = read("prompt_contracts", c.PromptContracts); err != nil {
			return nil, err
		}
	}
	more, err := read("prompt_contracts_append", c.PromptContractsAppend)
	if err != nil {
		return nil, err
	}
	return append(out, more...), nil
}

// Registers returns the lessons and runbooks paths to load: both "" when lessons_disabled is set.
// Neither lessons_path nor lessons_disabled is an error (no silent switch-off), and so is
// lessons_disabled with a path, or runbooks_path without lessons_path.
func (c Config) Registers() (lessonsPath, runbooksPath string, err error) {
	if c.LessonsDisabled {
		if c.LessonsPath != "" || c.RunbooksPath != "" {
			return "", "", fmt.Errorf("lessons_disabled: true cannot be combined with lessons_path / runbooks_path")
		}
		return "", "", nil
	}
	if c.LessonsPath == "" {
		return "", "", fmt.Errorf("lessons_path is required (set it, or set lessons_disabled: true to run with no lessons/runbooks context)")
	}
	return c.LessonsPath, c.RunbooksPath, nil
}

// OpaqueExtension is the profile_extension_schemas value that carries a key unchecked.
const OpaqueExtension = "opaque"

// ProfileLoadOptions are the profile.LoadOptions this configuration describes, the same at start,
// on reload and for a profile check. Opaque extension keys are named in the second result, so the
// caller logs them at every load.
func (c Config) ProfileLoadOptions(configDir string) (profile.LoadOptions, []string, error) {
	exts, opaque, err := c.profileExtensions(configDir)
	if err != nil {
		return profile.LoadOptions{}, nil, err
	}
	tmpl, err := profile.ParseCursorTemplate(c.CursorFileTemplate)
	if err != nil {
		return profile.LoadOptions{}, nil, err
	}
	// Only the default for now: the cursor tool writes the store at the default layout and takes
	// no such setting, so any other template would inject a cursor that tool never touches.
	if tmpl.String() != profile.DefaultCursorTemplate {
		return profile.LoadOptions{}, nil, fmt.Errorf("cursor_file_template %q: only the default %s is supported until the cursor tool takes the same setting", c.CursorFileTemplate, profile.DefaultCursorTemplate)
	}
	dir := c.PromptDir
	if dir != "" && !filepath.IsAbs(dir) {
		dir = filepath.Join(configDir, dir)
	}
	return profile.LoadOptions{
		Zones:         c.zones,
		Extensions:    exts,
		PromptDir:     dir,
		StateFiles:    append([]string(nil), c.PromptStateFiles...),
		FactsCommands: c.FactsCommands,
	}, opaque, nil
}

// profileExtensions resolves profile_extensions and their schemas. Every listed name needs an
// entry, a schema or OpaqueExtension, and every entry a listed name: a key with no declared shape
// would load unchecked, so a typo inside it would pass silently.
func (c Config) profileExtensions(configDir string) ([]profile.Extension, []string, error) {
	listed := make(map[string]bool, len(c.ProfileExtensions))
	exts := make([]profile.Extension, 0, len(c.ProfileExtensions))
	var opaque []string
	for _, name := range c.ProfileExtensions {
		if name == "" || listed[name] {
			return nil, nil, fmt.Errorf("profile_extensions: empty or repeated name %q", name)
		}
		listed[name] = true
		node, ok := c.ProfileExtensionSchemas[name]
		if !ok {
			return nil, nil, fmt.Errorf("profile_extensions %s: no profile_extension_schemas entry (give it a schema, or the value %q to carry it unchecked)", name, OpaqueExtension)
		}
		if node.Kind == yaml.ScalarNode && node.ShortTag() == "!!str" && node.Value == OpaqueExtension {
			exts = append(exts, profile.Extension{Name: name, Opaque: true})
			opaque = append(opaque, name)
			continue
		}
		schema, err := loadExtensionSchema(node, configDir)
		if err != nil {
			return nil, nil, fmt.Errorf("profile_extension_schemas %s: %w", name, err)
		}
		exts = append(exts, profile.Extension{Name: name, Schema: schema})
	}
	names := make([]string, 0, len(c.ProfileExtensionSchemas))
	for name := range c.ProfileExtensionSchemas {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !listed[name] {
			return nil, nil, fmt.Errorf("profile_extension_schemas %s: not listed in profile_extensions", name)
		}
	}
	return exts, opaque, nil
}

// loadExtensionSchema parses an inline schema, or reads the schema file a string names.
func loadExtensionSchema(node yaml.Node, configDir string) (*profile.Schema, error) {
	if node.Kind == yaml.ScalarNode && node.ShortTag() == "!!str" {
		path := node.Value
		if !filepath.IsAbs(path) {
			path = filepath.Join(configDir, path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return profile.ParseSchema(&doc)
	}
	return profile.ParseSchema(&node)
}
