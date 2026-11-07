// SPDX-License-Identifier: Apache-2.0

// Package grants checks and renders a profile's per-job MCP server grants.
//
// A profile names the server instances it may use, per lane (grants); the catalog says what each
// server kind runs and which environment keys a grant may set, and how (kinds). A job is given
// exactly its own lane's servers, rendered the same way whatever backend runs it, so no job sees
// another agent's servers and no grant can change what a kind runs.
//
// The catalog's records are homelab-next's MCP catalog (ADR-0024): `hnx mcp catalog render
// --client orchestrator` writes the catalog file and each profile's grants block. This package is
// the last word on what that render may contain: the render does not re-check these rules, and a
// test reads the committed render of examples/mcp in place and loads it here.
package grants

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
	"golang.org/x/sys/unix"

	"github.com/homelab-next/homelab-next/orchestrator/internal/pathscope"
)

// Kind is one MCP server program as the catalog defines it. Command, Args and the fixed Env are
// the catalog's alone; a grant can only set the env keys listed in AllowedEnv, each in the way
// the kind classifies it: pinned (AllowedValues or AllowedSets), bound to the granting profile
// (ProfileScope) or free in a declared shape (FreeEnv). A key the kind does not classify can never
// be set.
type Kind struct {
	Command    string            `yaml:"command"`
	Args       []string          `yaml:"args"`
	Timeout    int               `yaml:"timeout"`
	Env        map[string]string `yaml:"env"`
	AllowedEnv []string          `yaml:"allowed_env"`
	// AllowedValues pins grant-settable keys to the values the catalog lists. Every allowed_env
	// key that picks what runs or where a server reads, writes or connects (codeEnvRe) must be
	// pinned, so only the catalog decides what code runs and where it can reach.
	AllowedValues map[string][]string `yaml:"allowed_values"`
	// AllowedSets pins keys that only mean something together: a grant that sets any key named
	// only here (not in AllowedValues) must set every key of one listed set to exactly that set's
	// values, and nothing set-only beyond it (a script and the flag and pattern it accepts, say).
	AllowedSets []map[string]string `yaml:"allowed_sets"`
	// ProfileScope binds identity and scope keys to the profile that holds the grant.
	ProfileScope *ProfileScope `yaml:"profile_scope"`
	// FreeEnv lists the allowed_env keys a grant may set to a value of its own choosing, each with
	// the shape that value must have (freeShapes: "name", "int").
	FreeEnv map[string]string `yaml:"free_env"`
}

// freeShapes are the value shapes a FreeEnv key may declare.
var freeShapes = map[string]*regexp.Regexp{
	"name": nameRe,                                  // a lower-case name
	"int":  regexp.MustCompile(`^[1-9][0-9]{0,4}$`), // a positive count or timeout, at most 99999
}

// ProfileScope names a kind's env keys whose values the granting profile bounds. A grant may set
// them, but only to what its own profile already holds, so one profile cannot borrow another
// agent's identity or widen its scope through a grant:
//   - AgentKey keys must equal the profile's agent_key; AgentKeyLane keys must equal it on the real
//     lane and agent_key + "-shadow" on the shadow lane.
//   - Writable keys are comma-separated prefix lists. Every entry must be a clean writable prefix
//     under the tree's zones (never in a denied root, never "..", never absolute) and lie within
//     the profile's writable prefixes, and only when RootKey's value is one of ScopeRoots (the
//     roots the profile's scope describes): nothing is writable under any other root.
//   - Readable keys are comma-separated prefix lists, each entry a clean prefix (no "..", no
//     hidden segment such as .git or .env); under a ScopeRoots root each must also lie within the
//     profile's writable or readable prefixes. Under another (catalog-pinned) root they are read
//     scopes of that tree, which the profile's scope does not describe: each must lie within
//     RootReads[root] (none, for a root RootReads does not list, once RootReads is set).
//   - Prefix keys hold one directory prefix (clean, writable, ending in "/"). Under a ScopeRoots
//     root it must also lie within the grant's own Writable entries. VerdictPrefix keys (a subset
//     of Prefix) name a directory whose files a server replaces: each must also lie strictly under
//     the zones' findings root and neither within nor cover a shared write prefix
//     (pathscope.Zones.ValidateVerdictPrefix), so a verdict never replaces pending work.
//
// Lanes. A profile renders once per lane, and nothing a grant sets may cross lanes:
//   - Writable entries and Prefix values under a ScopeRoots root are lane-marked: on the shadow
//     lane each must carry a shadow token (pathscope.ShadowMarked) or lie within LaneShared
//     (prefixes both lanes write by design); on the real lane none may carry one. Nor may an entry
//     cover, or lie within, one of the profile's writable prefixes of the other lane (outside
//     LaneShared): a token alone does not place a path on a lane, so x/-shadow/ is still inside a
//     real x/.
//   - LaneValue keys must be "real" on the real lane and "shadow" on the shadow lane.
//   - LaneMarked keys (catalog-pinned paths such as a state file) must carry a shadow token on
//     the shadow lane and must not on the real lane.
//   - ShadowOnly keys (catalog-pinned) may be set on the shadow lane only.
//   - ShadowRequired ties lane keys to what runs: for an anchor key and each of its pinned values,
//     the LaneMarked/ShadowOnly keys a shadow grant running that value must set. A lane-marked
//     key is only checked when present, and a program that falls back to a real-lane path when
//     its key is unset would otherwise run on the shadow lane against real state.
//   - LaneHome binds catalog-pinned home paths to the lane: see LaneHome.
type ProfileScope struct {
	AgentKey     []string            `yaml:"agent_key"`
	AgentKeyLane []string            `yaml:"agent_key_lane"`
	RootKey      string              `yaml:"root_key"`
	ScopeRoots   []string            `yaml:"scope_roots"`
	RootReads    map[string][]string `yaml:"root_reads"`
	Writable     []string            `yaml:"writable"`
	Readable     []string            `yaml:"readable"`
	Prefix       []string            `yaml:"prefix"`
	// VerdictPrefix are the Prefix keys that name a verdict directory.
	VerdictPrefix []string  `yaml:"verdict_prefix"`
	LaneShared    []string  `yaml:"lane_shared"`
	LaneValue     []string  `yaml:"lane_value"`
	LaneMarked    []string  `yaml:"lane_marked"`
	ShadowOnly    []string  `yaml:"shadow_only"`
	LaneHome      *LaneHome `yaml:"lane_home"`
	// ShadowRequired: anchor key -> anchor value -> the lane keys a shadow grant with that value
	// must set (see above).
	ShadowRequired map[string]map[string][]string `yaml:"shadow_required"`
}

// LaneHome binds keys that name a per-lane home (a store on the real lane, the agent's own seeded
// copy of it on the shadow lane). The real lane's homes are Real; the shadow lane's only home is
// <base>/<agent_key> for a base in ShadowBases. Equal keys must name a home exactly; Within keys
// must name a home or a path under it. The keys stay catalog-pinned too (allowed_values): this
// narrows which pinned value each profile and lane may pick, so the real lane cannot point at
// another agent's shadow home, nor a shadow lane at the real store or a peer's home.
type LaneHome struct {
	Equal       []string `yaml:"equal"`
	Within      []string `yaml:"within"`
	Real        []string `yaml:"real"`
	ShadowBases []string `yaml:"shadow_bases"`
}

func (ps *ProfileScope) keys() []string {
	if ps == nil {
		return nil
	}
	var out []string
	for _, l := range [][]string{ps.AgentKey, ps.AgentKeyLane, ps.Writable, ps.Readable, ps.Prefix, ps.LaneValue} {
		out = append(out, l...)
	}
	return out
}

// laneKeys are the keys a ProfileScope lane-checks on top of their catalog pin.
func (ps *ProfileScope) laneKeys() []string {
	if ps == nil {
		return nil
	}
	out := append(append([]string{}, ps.LaneMarked...), ps.ShadowOnly...)
	if ps.LaneHome != nil {
		out = append(append(out, ps.LaneHome.Equal...), ps.LaneHome.Within...)
	}
	return out
}

// homes returns the lane's homes for o (nil when o has no usable agent key on the shadow lane).
func (h *LaneHome) homes(o Owner) []string {
	if !o.Shadow {
		return h.Real
	}
	if !nameRe.MatchString(o.AgentKey) {
		return nil
	}
	var out []string
	for _, b := range h.ShadowBases {
		out = append(out, strings.TrimSuffix(b, "/")+"/"+o.AgentKey)
	}
	return out
}

// Owner is what a grant's profile-bound keys are checked against: the granting profile's identity
// and scope, and the lane being rendered.
type Owner struct {
	AgentKey         string
	Shadow           bool
	WritablePrefixes []string
	ReadablePrefixes []string
}

// Catalog maps a kind name to its definition. It is used through LoadCatalog or ParseCatalog,
// which also give it the tree's zones its scope checks are decided against; a Catalog built
// another way has none, and refuses every grant that sets a scope key.
type Catalog struct {
	Kinds map[string]Kind `yaml:"kinds"`

	zones pathscope.Zones
}

// Grant is one server instance a profile is granted. Name is the server name the runner (and so
// the model) sees.
type Grant struct {
	Name    string            `yaml:"name"`
	Kind    string            `yaml:"kind"`
	Env     map[string]string `yaml:"env"`
	Timeout int               `yaml:"timeout"`
}

// Set is a profile's grants for the real and shadow lanes.
type Set struct {
	Real   []Grant `yaml:"real"`
	Shadow []Grant `yaml:"shadow"`
}

// Server is one rendered server: what the runner starts for a job.
type Server struct {
	Command string
	Args    []string
	Env     map[string]string // nil when empty
	Timeout int               // seconds; 0 = the runner's default
}

// UnmarshalYAML decodes a grants block strictly (unknown fields refused), wherever it is
// embedded: a typo'd lane or field (`reall:`, `knd:`, `evn:`) would otherwise grant nothing, or a
// server without its scoping env.
func (s *Set) UnmarshalYAML(value *yaml.Node) error {
	raw, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	type plain Set // no UnmarshalYAML: no recursion
	var out plain
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&out); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("grants: %w", err)
	}
	*s = Set(out)
	for _, g := range slices.Concat(s.Real, s.Shadow) {
		if err := checkGrantValues(g); err != nil {
			return fmt.Errorf("grants: %w", err)
		}
	}
	return nil
}

// checkGrantValues refuses a `${...}` reference in any grant-supplied value. A runner that writes
// the rendered servers into its own configuration may expand such references from its
// environment, so a grant value `${SOME_CREDENTIAL}` could hand that secret to an MCP server. A bare
// `$VAR` is not expanded and stays allowed. Values the catalog itself sets are not grants and may
// reference variables (a `secret:` reference renders as one).
func checkGrantValues(g Grant) error {
	for key, v := range g.Env {
		if strings.Contains(v, "${") {
			return fmt.Errorf("%w: server %q: %s=%q holds a ${...} reference, which a runner may expand from its environment", ErrInvalid, g.Name, key, v)
		}
	}
	return nil
}

// Lane returns the grants for one lane.
func (s Set) Lane(shadow bool) []Grant {
	if shadow {
		return s.Shadow
	}
	return s.Real
}

// IsZero reports whether the profile declares no grants at all.
func (s Set) IsZero() bool { return len(s.Real) == 0 && len(s.Shadow) == 0 }

// Validate refuses a set that grants one lane and not the other: every job of the empty lane
// would run with no servers at all, a silent loss of every tool rather than a refusal. A profile
// grants both lanes, or neither (it then dispatches with no per-job servers).
func (s Set) Validate() error {
	if (len(s.Real) == 0) != (len(s.Shadow) == 0) {
		empty := "shadow"
		if len(s.Real) == 0 {
			empty = "real"
		}
		return fmt.Errorf("%w: grants one lane and not the %s lane (grant both, or neither)", ErrInvalid, empty)
	}
	return nil
}

// Clone returns a deep copy.
func (s Set) Clone() Set {
	return Set{Real: cloneGrants(s.Real), Shadow: cloneGrants(s.Shadow)}
}

func cloneGrants(in []Grant) []Grant {
	if in == nil {
		return nil
	}
	out := make([]Grant, len(in))
	for i, g := range in {
		out[i] = g
		if g.Env != nil {
			out[i].Env = make(map[string]string, len(g.Env))
			for k, v := range g.Env {
				out[i].Env[k] = v
			}
		}
	}
	return out
}

// DeniedEnvPattern names the environment keys no grant may set and no kind may list as
// grant-settable, in any case: they change what code runs or how, not what a server is scoped to
// (the loader, the search path and home, the interpreters and package launchers, git, the config
// directories they read, the container CLI's own settings, the TLS stack's configuration and key
// log, every proxy, the C library's module, locale, resolver and allocator knobs, other
// interpreters' option variables and the shell's). It is homelab-next's DENIED_ENV
// (homelabnext/mcp/servers.py) character for character, which tests/mcp/test_mcp_clients.py holds
// equal, so a record the catalog accepts and a grant this package accepts are refused for the same
// keys.
const DeniedEnvPattern = `(?:LD_|DYLD_|PYTHON|NODE_|NPM_CONFIG_|UV_|PIP_|PIPX_|BUN_|COREPACK_|YARN_|PNPM_|GIT_|CONTAINER|XDG_|BUILDKIT|COMPOSE_|DOCKER_(?:TLS|CONTENT_TRUST|CLI_)|OPENSSL_|SSL_CERT_|MALLOC_|BASH_FUNC_).*|DOCKER_(?:HOST|CONFIG|CERT_PATH|CONTEXT|API_VERSION|DEFAULT_PLATFORM|BUILDKIT|CUSTOM_HEADERS)|PATH|HOME|SHELL|BASH_ENV|ENV|HERMES_HOME|NODE|NPM_TOKEN|\w*_PROXY|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|SSLKEYLOGFILE|GCONV_PATH|LOCPATH|NLSPATH|HOSTALIASES|RES_OPTIONS|LOCALDOMAIN|GLIBC_TUNABLES|TZDIR|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS|PERL5OPT|PERL5LIB|PERLLIB|RUBYOPT|RUBYLIB|SHELLOPTS|BASHOPTS|PS4`

var (
	nameRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	deniedEnvRe = regexp.MustCompile(`(?i)^(?:` + DeniedEnvPattern + `)$`)
)

// codeEnvRe names grant-settable keys that pick what code runs (a script, an interpreter, its
// args) or where a server reads, writes or connects (a root, store, dir, file, state, URL, host,
// target). A catalog must pin each one to listed values (Kind.AllowedValues or AllowedSets). The
// caller-argument keys (_FLAG, _PATTERN, _ARG_NAME) decide what a model may append to a pinned
// script's command line, so they are pinned too.
var codeEnvRe = regexp.MustCompile(`(?i)(?:_PATH|_INTERPRETER|_PYTHON|_ARGS|_ROOT|_VAULT|_DIR|_FILE|_STATE|_URL|_HOST|_TARGET|_FLAG|_PATTERN|_ARG_NAME)$|^HISTORY$`)

// scopeEnvRe names grant-settable keys that pick whose identity a server acts as or which prefixes
// it may read or write, in any spelling a server might use for one (_PREFIX, _PREFIXES,
// _PREFIX_LIST, _AGENT_KEY, _BY, _SCOPE, _WRITE_SCOPE, _LIST). A catalog must pin each one or bind
// it to the granting profile; it can never be free_env. This is the backstop: the rule itself is
// the allowlist (every allowed_env key pinned, bound or free_env with a shape).
var scopeEnvRe = regexp.MustCompile(`(?i)(?:_PREFIX\w*|_AGENT_KEY|_BY|_SCOPE|_LIST)$`)

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("invalid grant")

// LoadCatalog reads and validates a catalog file (ParseCatalog).
func LoadCatalog(file string, zones pathscope.Zones) (*Catalog, error) {
	data, err := ReadConfigFile(file, MaxCatalogBytes)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	c, err := ParseCatalog(data, zones)
	if err != nil {
		return nil, fmt.Errorf("catalog %s: %w", file, err)
	}
	return c, nil
}

// MaxCatalogBytes bounds a catalog file.
const MaxCatalogBytes = 4 << 20

// ReadConfigFile reads a configuration file the controller trusts: a regular file, opened without
// following a symbolic link in its last component, of at most max bytes. The size is checked on
// the open descriptor, so a file swapped after a check cannot be read instead.
func ReadConfigFile(file string, max int64) ([]byte, error) {
	f, err := os.OpenFile(file, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", file)
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%s: larger than %d bytes", file, max)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s: larger than %d bytes", file, max)
	}
	return data, nil
}

// ParseCatalog decodes a catalog strictly (unknown fields refused, a repeated key refused) and
// validates every kind against zones, which must be validated (pathscope.NewZones).
func ParseCatalog(data []byte, zones pathscope.Zones) (*Catalog, error) {
	if !zones.Validated() {
		return nil, fmt.Errorf("%w: the catalog needs validated scope zones (pathscope.NewZones)", ErrInvalid)
	}
	var c Catalog
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	c.zones = zones
	names := make([]string, 0, len(c.Kinds))
	for name := range c.Kinds {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := c.checkKind(name, c.Kinds[name]); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

func (c *Catalog) checkKind(name string, k Kind) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("kind %q: bad name", name)
	}
	if k.Command == "" {
		return fmt.Errorf("kind %q: command is required", name)
	}
	if err := k.checkNames(); err != nil {
		return fmt.Errorf("kind %q: %w", name, err)
	}
	for key := range k.AllowedValues {
		if !slices.Contains(k.AllowedEnv, key) {
			return fmt.Errorf("kind %q: allowed_values names %s, which is not in allowed_env", name, key)
		}
	}
	if err := k.checkSets(); err != nil {
		return fmt.Errorf("kind %q: %w", name, err)
	}
	if err := k.checkProfileScope(c.zones); err != nil {
		return fmt.Errorf("kind %q: %w", name, err)
	}
	if err := k.checkFixedEnv(c.zones); err != nil {
		return fmt.Errorf("kind %q: %w", name, err)
	}
	for key, shape := range k.FreeEnv {
		if !slices.Contains(k.AllowedEnv, key) {
			return fmt.Errorf("kind %q: free_env names %s, which is not in allowed_env", name, key)
		}
		if freeShapes[shape] == nil {
			return fmt.Errorf("kind %q: free_env %s has unknown shape %q (name, int)", name, key, shape)
		}
	}
	for _, key := range k.AllowedEnv {
		if deniedEnv(key) {
			return fmt.Errorf("kind %q: env key %s may never be grant-settable", name, key)
		}
		pinned := len(k.AllowedValues[key]) > 0 || k.inSet(key)
		bound := slices.Contains(k.ProfileScope.keys(), key)
		_, free := k.FreeEnv[key]
		switch {
		case codeEnvRe.MatchString(key) && !pinned:
			return fmt.Errorf("kind %q: env key %s picks what runs or where it reaches; pin it in allowed_values", name, key)
		case scopeEnvRe.MatchString(key) && !pinned && !bound:
			return fmt.Errorf("kind %q: env key %s picks an identity or a scope; pin it in allowed_values or bind it in profile_scope", name, key)
		case free && (pinned || bound):
			return fmt.Errorf("kind %q: env key %s is free_env and also pinned or profile-bound", name, key)
		case !pinned && !bound && !free:
			return fmt.Errorf("kind %q: env key %s is not pinned (allowed_values/allowed_sets), bound (profile_scope) or free_env with a shape; a grant could set it to anything", name, key)
		case identityKeyRe.MatchString(key) && !bound:
			// a pinned identity would let every profile granted the kind act as that one agent
			return fmt.Errorf("kind %q: env key %s is an identity; bind it in profile_scope (agent_key or agent_key_lane), never pin it", name, key)
		}
		if scopeEnvRe.MatchString(key) {
			for _, v := range k.pins(key) {
				if err := checkScopeValue(c.zones, key, v); err != nil {
					return fmt.Errorf("kind %q: a pinned value of %s: %w", name, key, err)
				}
			}
		}
	}
	return nil
}

// pins are every value the catalog pins key to, in allowed_values and in allowed_sets.
func (k Kind) pins(key string) []string {
	out := slices.Clone(k.AllowedValues[key])
	for _, set := range k.AllowedSets {
		if v, ok := set[key]; ok {
			out = append(out, v)
		}
	}
	return out
}

// checkScopeValue holds a scope-shaped key's value (a comma-separated prefix list) to the zones:
// every entry a clean prefix, a writable one unless the key names a read scope.
func checkScopeValue(zones pathscope.Zones, key, v string) error {
	for _, e := range splitPrefixes(v) {
		if err := zones.ValidatePrefix(e, !readScopeKeyRe.MatchString(key)); err != nil {
			return err
		}
	}
	return nil
}

// envNameRe is an environment variable name: anything else could not be set as one, or would be
// parsed differently by the program that receives it.
var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// MaxTimeout bounds a kind's or a grant's timeout, in seconds (a day).
const MaxTimeout = 86400

// checkNames holds every env key a kind names to envNameRe, and its timeout to 0..MaxTimeout.
func (k Kind) checkNames() error {
	if k.Timeout < 0 || k.Timeout > MaxTimeout {
		return fmt.Errorf("timeout %d: want 0 to %d seconds", k.Timeout, MaxTimeout)
	}
	names := slices.Clone(k.AllowedEnv)
	for _, m := range []map[string]string{k.Env, k.FreeEnv} {
		for key := range m {
			names = append(names, key)
		}
	}
	for key := range k.AllowedValues {
		names = append(names, key)
	}
	for _, set := range k.AllowedSets {
		for key := range set {
			names = append(names, key)
		}
	}
	names = append(names, k.ProfileScope.keys()...)
	names = append(names, k.ProfileScope.laneKeys()...)
	if k.ProfileScope != nil && k.ProfileScope.RootKey != "" {
		names = append(names, k.ProfileScope.RootKey)
	}
	for _, key := range names {
		if !envNameRe.MatchString(key) {
			return fmt.Errorf("env key %q is not a variable name", clip(key))
		}
	}
	return nil
}

// clip bounds an untrusted string quoted in an error, never cutting a UTF-8 sequence.
func clip(s string) string {
	const max = 80
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// readScopeKeyRe names scope keys whose entries are read scopes; every other scope-shaped key (a
// writable list, a findings prefix, a write scope) is checked as a writable prefix.
var readScopeKeyRe = regexp.MustCompile(`(?i)READ`)

// identityKeyRe names keys that carry an identity (scopeEnvRe's _AGENT_KEY and _BY).
var identityKeyRe = regexp.MustCompile(`(?i)(?:_AGENT_KEY|_BY)$`)

// checkFixedEnv holds the catalog's own fixed env to the rules a grant's value meets: no denied
// key; a pinned key fixed to one of its pins; a free key in its shape; no profile-bound or
// lane-checked key (fixed once for every profile and both lanes, it would bypass the binding); no
// fixed identity; and every scope-shaped key's entries clean prefixes under the zones, so a
// catalog cannot fix a writable prefix in a denied root for every grant of a kind.
func (k Kind) checkFixedEnv(zones pathscope.Zones) error {
	bound := append(k.ProfileScope.keys(), k.ProfileScope.laneKeys()...)
	keys := make([]string, 0, len(k.Env))
	for key := range k.Env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		v := k.Env[key]
		switch {
		case deniedEnv(key):
			return fmt.Errorf("env %s may never be set (it changes what code runs or how)", key)
		case slices.Contains(bound, key):
			return fmt.Errorf("env %s is profile-bound or lane-checked in profile_scope and cannot be fixed for every profile", key)
		case identityKeyRe.MatchString(key):
			return fmt.Errorf("env %s is an identity and cannot be fixed for every profile", key)
		}
		if pins, ok := k.AllowedValues[key]; ok && !slices.Contains(pins, v) {
			return fmt.Errorf("env %s=%q is not one of its allowed_values", key, v)
		}
		if shape, ok := k.FreeEnv[key]; ok {
			if re := freeShapes[shape]; re == nil || !re.MatchString(v) {
				return fmt.Errorf("env %s=%q is not a %s value", key, v, shape)
			}
		}
		if scopeEnvRe.MatchString(key) {
			for _, e := range splitPrefixes(v) {
				if err := zones.ValidatePrefix(e, !readScopeKeyRe.MatchString(key)); err != nil {
					return fmt.Errorf("env %s: %w", key, err)
				}
			}
		}
	}
	return nil
}

// inSet reports whether key is named by any of the kind's allowed_sets.
func (k Kind) inSet(key string) bool {
	for _, set := range k.AllowedSets {
		if _, ok := set[key]; ok {
			return true
		}
	}
	return false
}

// setOnly reports whether key is pinned only through allowed_sets.
func (k Kind) setOnly(key string) bool {
	_, pinned := k.AllowedValues[key]
	return !pinned && k.inSet(key)
}

func (k Kind) checkSets() error {
	for i, set := range k.AllowedSets {
		if len(set) == 0 {
			return fmt.Errorf("allowed_sets[%d] is empty", i)
		}
		only := 0
		for key, v := range set {
			if !slices.Contains(k.AllowedEnv, key) {
				return fmt.Errorf("allowed_sets[%d] names %s, which is not in allowed_env", i, key)
			}
			if pinned, ok := k.AllowedValues[key]; ok {
				if !slices.Contains(pinned, v) {
					return fmt.Errorf("allowed_sets[%d]: %s=%q is not one of its allowed_values", i, key, v)
				}
			} else {
				only++
			}
		}
		if only == 0 {
			return fmt.Errorf("allowed_sets[%d] pins nothing allowed_values does not already pin", i)
		}
	}
	return nil
}

func (k Kind) checkProfileScope(zones pathscope.Zones) error {
	ps := k.ProfileScope
	if ps == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, key := range ps.keys() {
		if seen[key] {
			return fmt.Errorf("profile_scope names %s twice", key)
		}
		seen[key] = true
		if !slices.Contains(k.AllowedEnv, key) {
			return fmt.Errorf("profile_scope names %s, which is not in allowed_env", key)
		}
		if _, ok := k.AllowedValues[key]; ok || k.inSet(key) {
			return fmt.Errorf("profile_scope names %s, which allowed_values or allowed_sets also pins", key)
		}
	}
	for _, key := range ps.VerdictPrefix {
		if !slices.Contains(ps.Prefix, key) {
			return fmt.Errorf("profile_scope verdict_prefix %s is not one of its prefix keys", key)
		}
	}
	for _, key := range ps.laneKeys() {
		if seen[key] {
			return fmt.Errorf("profile_scope names %s twice", key)
		}
		seen[key] = true
		if len(k.AllowedValues[key]) == 0 {
			return fmt.Errorf("profile_scope lane-checks %s, which must also be pinned in allowed_values", key)
		}
	}
	for anchor, byValue := range ps.ShadowRequired {
		pins := k.AllowedValues[anchor]
		if len(pins) == 0 || slices.Contains(ps.laneKeys(), anchor) {
			return fmt.Errorf("profile_scope shadow_required anchor %s must be a pinned key that is not lane-checked itself", anchor)
		}
		for v, keys := range byValue {
			if !slices.Contains(pins, v) {
				return fmt.Errorf("profile_scope shadow_required: %s=%q is not one of its allowed_values", anchor, v)
			}
			if len(keys) == 0 {
				return fmt.Errorf("profile_scope shadow_required: %s=%q requires nothing", anchor, v)
			}
			for _, key := range keys {
				if !slices.Contains(ps.LaneMarked, key) && !slices.Contains(ps.ShadowOnly, key) {
					return fmt.Errorf("profile_scope shadow_required: %s is not lane_marked or shadow_only", key)
				}
			}
		}
	}
	if h := ps.LaneHome; h != nil {
		if len(h.Equal)+len(h.Within) == 0 || len(h.Real) == 0 || len(h.ShadowBases) == 0 {
			return fmt.Errorf("profile_scope lane_home needs equal/within keys, real homes and shadow_bases")
		}
		for _, d := range slices.Concat(h.Real, h.ShadowBases) {
			if !path.IsAbs(d) || path.Clean(d) != d || d == "/" {
				return fmt.Errorf("profile_scope lane_home: %q is not a clean absolute directory", d)
			}
		}
	}
	for _, e := range ps.LaneShared {
		if err := zones.ValidatePrefix(e, true); err != nil {
			return fmt.Errorf("profile_scope lane_shared: %w", err)
		}
		if pathscope.ShadowMarked(e) {
			return fmt.Errorf("profile_scope lane_shared %q is a shadow prefix", e)
		}
		// the verdict check knows the zones' shared prefixes only: a lane-shared prefix outside
		// them would be writable by both lanes and yet not kept clear of verdict directories
		if !pathscope.Within(e, zones.SharedWrite) {
			return fmt.Errorf("profile_scope lane_shared %q is not within the scope zones' shared_write", e)
		}
	}
	if len(ps.Writable)+len(ps.Readable) == 0 {
		if ps.RootKey != "" || len(ps.ScopeRoots) > 0 {
			return fmt.Errorf("profile_scope sets root_key/scope_roots without writable or readable keys")
		}
		return nil
	}
	if ps.RootKey == "" {
		return fmt.Errorf("profile_scope has writable/readable keys but no root_key")
	}
	roots := append([]string{}, k.AllowedValues[ps.RootKey]...)
	if v, ok := k.Env[ps.RootKey]; ok {
		roots = append(roots, v)
	}
	if len(roots) == 0 {
		return fmt.Errorf("profile_scope root_key %s must be pinned in allowed_values or fixed in env", ps.RootKey)
	}
	if len(ps.Writable) > 0 && len(ps.ScopeRoots) == 0 {
		return fmt.Errorf("profile_scope has writable keys but no scope_roots, so nothing could be written")
	}
	for _, r := range ps.ScopeRoots {
		if !slices.Contains(roots, r) {
			return fmt.Errorf("profile_scope scope_roots names %q, which %s can never be", r, ps.RootKey)
		}
	}
	for r, entries := range ps.RootReads {
		if !slices.Contains(roots, r) || slices.Contains(ps.ScopeRoots, r) {
			return fmt.Errorf("profile_scope root_reads names %q, which is not a pinned %s outside scope_roots", r, ps.RootKey)
		}
		for _, e := range entries {
			if err := zones.ValidatePrefix(e, false); err != nil {
				return fmt.Errorf("profile_scope root_reads[%s]: %w", r, err)
			}
		}
	}
	return nil
}

// splitPrefixes splits a comma-separated prefix list (empty entries dropped; entries are not
// trimmed, so a spaced entry fails the prefix check).
func splitPrefixes(v string) []string {
	var out []string
	for _, e := range strings.Split(v, ",") {
		if e != "" {
			out = append(out, e)
		}
	}
	return out
}

// checkOwner applies the kind's ProfileScope to one grant (see ProfileScope for the rules).
func (k Kind) checkOwner(g Grant, env map[string]string, o Owner, zones pathscope.Zones) error {
	ps := k.ProfileScope
	if ps == nil {
		return nil
	}
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: server %q (kind %s): "+format, append([]any{ErrInvalid, g.Name, g.Kind}, a...)...)
	}
	for _, key := range ps.AgentKey {
		if v, ok := g.Env[key]; ok && (o.AgentKey == "" || v != o.AgentKey) {
			return bad("%s=%q is not this profile's agent_key %q", key, v, o.AgentKey)
		}
	}
	lane := laneName(o.Shadow)
	for _, key := range ps.AgentKeyLane {
		want := o.AgentKey
		if o.Shadow {
			want += "-shadow"
		}
		if v, ok := g.Env[key]; ok && (o.AgentKey == "" || v != want) {
			return bad("%s=%q is not %q (this profile's agent_key for the %s lane)", key, v, want, lane)
		}
	}
	for _, key := range ps.LaneValue {
		if v, ok := g.Env[key]; ok && v != lane {
			return bad("%s=%q on the %s lane; it must be %q", key, v, lane, lane)
		}
	}
	for _, key := range ps.LaneMarked {
		if v, ok := g.Env[key]; ok && pathscope.ShadowMarked(v) != o.Shadow {
			return bad("%s=%q is not a %s-lane value", key, v, lane)
		}
	}
	for _, key := range ps.ShadowOnly {
		if _, ok := g.Env[key]; ok && !o.Shadow {
			return bad("%s may be set on the shadow lane only", key)
		}
	}
	if o.Shadow {
		anchors := make([]string, 0, len(ps.ShadowRequired))
		for a := range ps.ShadowRequired {
			anchors = append(anchors, a)
		}
		sort.Strings(anchors)
		for _, anchor := range anchors {
			v, ok := env[anchor]
			if !ok {
				continue
			}
			for _, key := range ps.ShadowRequired[anchor][v] {
				if _, set := g.Env[key]; !set {
					return bad("%s=%q on the shadow lane must also set %s (unset, it falls back to real-lane state)", anchor, v, key)
				}
			}
		}
	}
	if h := ps.LaneHome; h != nil {
		homes := h.homes(o)
		for _, key := range h.Equal {
			if v, ok := g.Env[key]; ok && !slices.Contains(homes, v) {
				return bad("%s=%q is not this profile's %s-lane home (%s)", key, v, lane, strings.Join(homes, ", "))
			}
		}
		for _, key := range h.Within {
			if v, ok := g.Env[key]; ok && !underAny(v, homes) {
				return bad("%s=%q is not under this profile's %s-lane home (%s)", key, v, lane, strings.Join(homes, ", "))
			}
		}
	}
	root := env[ps.RootKey]
	scopeRoot := ps.RootKey != "" && slices.Contains(ps.ScopeRoots, root)
	// A prefix means nothing without the root it is relative to, and a server started without one
	// would resolve it against whatever its default is: refuse rather than guess.
	if ps.RootKey != "" && root == "" {
		for _, key := range slices.Concat(ps.Writable, ps.Readable, ps.Prefix) {
			if _, ok := g.Env[key]; ok {
				return bad("%s is set but %s is not; a prefix needs its root", key, ps.RootKey)
			}
		}
	}
	// laneOK applies the write-lane rule to one writable entry or prefix (see ProfileScope).
	laneOK := func(key, e string) error {
		if o.Shadow && !pathscope.ShadowMarked(e) && !pathscope.Within(e, ps.LaneShared) {
			return bad("%s entry %q is not a shadow-lane prefix (a -shadow path, or one of %s)", key, e, strings.Join(ps.LaneShared, ", "))
		}
		if !o.Shadow && pathscope.ShadowMarked(e) {
			return bad("%s entry %q is a shadow-lane prefix, and this is the real lane", key, e)
		}
		// Nor may an entry span the other lane, or lie inside it: a real-lane parent would cover
		// the profile's -shadow prefix as well, and a shadow-lane x/-shadow/ carries a shadow
		// token yet sits inside the real x/.
		for _, p := range o.WritablePrefixes {
			if pathscope.ShadowMarked(p) == o.Shadow || pathscope.Within(p, ps.LaneShared) {
				continue
			}
			if pathscope.Within(p, []string{e}) {
				return bad("%s entry %q covers %q, a %s-lane prefix of this profile", key, e, p, laneName(!o.Shadow))
			}
			if pathscope.Within(e, []string{p}) {
				return bad("%s entry %q lies within %q, a %s-lane prefix of this profile", key, e, p, laneName(!o.Shadow))
			}
		}
		return nil
	}
	var granted []string
	for _, key := range ps.Writable {
		entries := splitPrefixes(g.Env[key])
		if len(entries) > 0 && !scopeRoot {
			return bad("%s may not grant writes under %s=%q; only under %s", key, ps.RootKey, root, strings.Join(ps.ScopeRoots, ", "))
		}
		for _, e := range entries {
			if err := zones.ValidatePrefix(e, true); err != nil {
				return bad("%s: %v", key, err)
			}
			if !pathscope.Within(e, o.WritablePrefixes) {
				return bad("%s entry %q is not within this profile's writable prefixes", key, e)
			}
			if err := laneOK(key, e); err != nil {
				return err
			}
		}
		granted = append(granted, entries...)
	}
	both := slices.Concat(o.WritablePrefixes, o.ReadablePrefixes)
	for _, key := range ps.Readable {
		for _, e := range splitPrefixes(g.Env[key]) {
			if err := zones.ValidatePrefix(e, false); err != nil {
				return bad("%s: %v", key, err)
			}
			if scopeRoot && !pathscope.Within(e, both) {
				return bad("%s entry %q is not within this profile's scope", key, e)
			}
			if !scopeRoot && ps.RootReads != nil && !pathscope.Within(e, ps.RootReads[root]) {
				return bad("%s entry %q is not one of the catalog's readable prefixes under %s=%q", key, e, ps.RootKey, root)
			}
		}
	}
	for _, key := range ps.Prefix {
		v, ok := g.Env[key]
		if !ok {
			continue
		}
		// A prefix names the directory the server writes its own files into: clean, writable and
		// ending in "/".
		if err := zones.ValidateDirPrefix(v); err != nil {
			return bad("%s: %v", key, err)
		}
		// A verdict directory's files are replaced: it lies under the findings root and clear of
		// every shared write prefix, so a verdict can never replace pending work.
		if slices.Contains(ps.VerdictPrefix, key) {
			if err := zones.ValidateVerdictPrefix(v); err != nil {
				return bad("%s: %v", key, err)
			}
		}
		// Under a pinned root other than a scope root nothing is writable, so a prefix there is inert.
		if !scopeRoot {
			continue
		}
		if !pathscope.Within(v, granted) {
			return bad("%s=%q is not within this grant's own writable prefixes", key, v)
		}
		if err := laneOK(key, v); err != nil {
			return err
		}
	}
	return nil
}

// underAny reports whether p is one of dirs or a clean absolute path under one of them.
func underAny(p string, dirs []string) bool {
	if path.Clean(p) != p || !path.IsAbs(p) {
		return false
	}
	for _, d := range dirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// checkSetsFor refuses a grant that sets a set-only key without matching one allowed set exactly.
func (k Kind) checkSetsFor(g Grant) error {
	var used []string
	for key := range g.Env {
		if k.setOnly(key) {
			used = append(used, key)
		}
	}
	if len(used) == 0 {
		return nil
	}
	sort.Strings(used)
next:
	for _, set := range k.AllowedSets {
		for key, v := range set {
			if gv, ok := g.Env[key]; !ok || gv != v {
				continue next
			}
		}
		for _, key := range used {
			if _, ok := set[key]; !ok {
				continue next
			}
		}
		return nil
	}
	return fmt.Errorf("%w: server %q (kind %s): %s must match one of the catalog's allowed_sets exactly", ErrInvalid, g.Name, g.Kind, strings.Join(used, ", "))
}

func laneName(shadow bool) string {
	if shadow {
		return "shadow"
	}
	return "real"
}

// Render turns one lane's grants into the servers a job is given, by server name. It fails closed
// on any unknown kind, duplicate or malformed name, env key the kind does not allow, value the
// catalog does not pin, or profile-bound value (Kind.ProfileScope) the owning profile o does not
// hold.
func (c *Catalog) Render(gs []Grant, o Owner) (map[string]Server, error) {
	out := make(map[string]Server, len(gs))
	for _, g := range gs {
		if !nameRe.MatchString(g.Name) {
			return nil, fmt.Errorf("%w: server name %q", ErrInvalid, g.Name)
		}
		if _, dup := out[g.Name]; dup {
			return nil, fmt.Errorf("%w: server %q granted twice", ErrInvalid, g.Name)
		}
		if err := checkGrantValues(g); err != nil {
			return nil, err
		}
		k, ok := c.Kinds[g.Kind]
		if !ok {
			return nil, fmt.Errorf("%w: server %q: unknown kind %q", ErrInvalid, g.Name, g.Kind)
		}
		env := make(map[string]string, len(k.Env)+len(g.Env))
		for key, v := range k.Env {
			env[key] = v
		}
		if g.Timeout < 0 || g.Timeout > MaxTimeout {
			return nil, fmt.Errorf("%w: server %q: timeout %d: want 0 to %d seconds", ErrInvalid, g.Name, g.Timeout, MaxTimeout)
		}
		if err := k.checkNames(); err != nil {
			return nil, fmt.Errorf("%w: server %q (kind %s): %v", ErrInvalid, g.Name, g.Kind, err)
		}
		for key, v := range g.Env {
			if !envNameRe.MatchString(key) {
				return nil, fmt.Errorf("%w: server %q: env key %q is not a variable name", ErrInvalid, g.Name, clip(key))
			}
			bound := slices.Contains(k.ProfileScope.keys(), key)
			if identityKeyRe.MatchString(key) && !bound {
				return nil, fmt.Errorf("%w: server %q (kind %s): %s is an identity the catalog does not bind to the profile", ErrInvalid, g.Name, g.Kind, key)
			}
			if scopeEnvRe.MatchString(key) && !bound {
				if err := checkScopeValue(c.zones, key, v); err != nil {
					return nil, fmt.Errorf("%w: server %q (kind %s): %s: %v", ErrInvalid, g.Name, g.Kind, key, err)
				}
			}
			if deniedEnv(key) || !slices.Contains(k.AllowedEnv, key) {
				return nil, fmt.Errorf("%w: server %q (kind %s) may not set env %s", ErrInvalid, g.Name, g.Kind, key)
			}
			switch pinned, ok := k.AllowedValues[key]; {
			case ok:
				if !slices.Contains(pinned, v) {
					return nil, fmt.Errorf("%w: server %q (kind %s): %s=%q is not one of the catalog's values", ErrInvalid, g.Name, g.Kind, key, v)
				}
			case k.setOnly(key), slices.Contains(k.ProfileScope.keys(), key):
				// checked below, against the allowed sets / the owning profile
			case k.FreeEnv[key] != "":
				if re := freeShapes[k.FreeEnv[key]]; re == nil || !re.MatchString(v) {
					return nil, fmt.Errorf("%w: server %q (kind %s): %s=%q is not a %s value", ErrInvalid, g.Name, g.Kind, key, v, k.FreeEnv[key])
				}
			default:
				// ParseCatalog refuses an unclassified key; a catalog built another way gets the
				// same answer here.
				return nil, fmt.Errorf("%w: server %q (kind %s): %s is not pinned, profile-bound or free_env in the catalog", ErrInvalid, g.Name, g.Kind, key)
			}
			env[key] = v
		}
		if err := k.checkSetsFor(g); err != nil {
			return nil, err
		}
		if err := k.checkOwner(g, env, o, c.zones); err != nil {
			return nil, err
		}
		s := Server{Command: k.Command, Args: append([]string{}, k.Args...)}
		if len(env) > 0 {
			s.Env = env
		}
		if g.Timeout > 0 {
			s.Timeout = g.Timeout
		} else if k.Timeout > 0 {
			s.Timeout = k.Timeout
		}
		out[g.Name] = s
	}
	return out, nil
}

// Names returns the granted server names, sorted.
func Names(gs []Grant) []string {
	names := make([]string, 0, len(gs))
	for _, g := range gs {
		names = append(names, g.Name)
	}
	sort.Strings(names)
	return names
}

// deniedEnv reports whether key may never be set by a grant (or listed as grant-settable by a
// catalog kind), in any case and ignoring surrounding space.
func deniedEnv(key string) bool { return deniedEnvRe.MatchString(strings.TrimSpace(key)) }

// DeniedEnv is deniedEnv for other packages that pass operator-named variables to a child process
// (a profile facts command's env): the same names change what code runs or how, wherever they go.
func DeniedEnv(key string) bool { return deniedEnv(key) }
