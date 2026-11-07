// SPDX-License-Identifier: Apache-2.0

// Package profile loads the controller's dispatch profiles: one YAML file per agent, naming what
// the agent may use (tools, a path scope, MCP grants per lane), how its prompt is built and where
// it may run. A job's profile is always resolved here, from the registry, never taken from the
// caller.
//
// The dispatch profile is a derived artifact of homelab-next's agent profiles
// (schemas/platform/agent_profile.schema.json): schemas/platform/orchestrator_profile.schema.json
// documents what this loader accepts, and the loader stays the authority (a test holds the schema
// to the Go types). Rendering it from the agent profile is a follow-up, as the MCP render already
// does for the grants block.
package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/homelab-next/homelab-next/orchestrator/internal/grants"
	"github.com/homelab-next/homelab-next/orchestrator/internal/pathscope"
)

// PathScope is the profile's path scope in the shared tree (pathscope): the prefixes it may write
// and read. Every entry is checked against the controller's scope zones at load.
type PathScope struct {
	WritablePrefixes []string `yaml:"writable_prefixes"`
	ReadablePrefixes []string `yaml:"readable_prefixes"`
}

// Toolsets names, per lane, the toolsets a runner enables for this agent when the profile has no
// grants (opaque to the controller: the runner reads them).
type Toolsets struct {
	Real   string `yaml:"real"`
	Shadow string `yaml:"shadow"`
}

// BackendAffinity constrains which local backends this profile's calls may land on. The zero
// value imposes no constraint.
type BackendAffinity struct {
	// RequireTags: a backend must carry every tag.
	RequireTags []string `yaml:"require_tags"`
	// ExcludeBackends are backend names never used.
	ExcludeBackends []string `yaml:"exclude_backends"`
	// MinContext: the backend's declared context window must be at least this many tokens; a
	// backend that declares none does not qualify.
	MinContext int `yaml:"min_context"`
	// Exclusive: the run has its backend alone.
	Exclusive bool `yaml:"exclusive"`
}

// Profile is the one resolved, immutable profile a run gets before dispatch.
type Profile struct {
	ID           string    `yaml:"id"`
	AgentKey     string    `yaml:"agent_key"`
	AllowedTools []string  `yaml:"allowed_tools"`
	PathScope    PathScope `yaml:"path_scope"`
	Toolsets     Toolsets  `yaml:"toolsets"`
	// DefaultTaskDescription is used when a submitted job's task is empty, so a caller never
	// dispatches this agent with a blank prompt by accident. Empty: such a job fails with a reason.
	DefaultTaskDescription string `yaml:"default_task_description"`
	// PromptContext is the prompt data beyond the task text; see its type.
	PromptContext PromptContext `yaml:"prompt_context"`
	// InjectOwnState is the older spelling of prompt_context.own_state. It needs an allowed
	// prompt_context.state_file and cannot be combined with facts or known_incidents_key.
	InjectOwnState bool `yaml:"inject_own_state"`
	// LocalOnly: the job never falls back to a cloud backend; when every local attempt fails, it
	// fails with the local reason (for an agent whose inputs must never reach a cloud model).
	LocalOnly bool `yaml:"local_only"`
	// BackendAffinity constrains the local backends this profile's calls may land on.
	BackendAffinity BackendAffinity `yaml:"backend_affinity"`
	// MaxAttempts bounds how many times one job's whole attempt chain runs before the job fails.
	// Zero or one: one attempt. A retry keeps the run id; it is never made after a job deadline, a
	// timeout ceiling, a turn cap or a cancel.
	MaxAttempts int `yaml:"max_attempts"`
	// Grants are the MCP server instances this profile may use, per lane (package grants). A job
	// is given only its lane's servers. Both lanes or neither (grants.Set.Validate).
	Grants grants.Set `yaml:"grants"`

	// Extensions holds the top-level keys this package does not define, by name. The loader
	// accepts only names the controller config lists (LoadOptions.Extensions); any other unknown
	// key fails the load.
	Extensions map[string]yaml.Node `yaml:",inline"`

	// Revision identifies the version of this profile a job ran against: never from YAML, a short
	// digest of the file and every file it pulls in, so it changes exactly when the content does.
	Revision string `yaml:"-"`

	findingsRoot string // the zones' findings root, for FindingsPrefix
}

// MaxProfileBytes bounds one profile file (read without following a symbolic link).
const MaxProfileBytes = 1 << 20

// MaxAgentKeyLen bounds an agent key.
const MaxAgentKeyLen = 64

// agentKeyRe is an agent key: the server-name shape of the grants (lower case, digits, "-" and
// "_"), so a key is safe in a path segment, a server name and a shadow home.
var agentKeyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// FindingsPrefix returns this profile's own findings directory for the real or shadow lane: the
// one writable prefix under the scope zones' findings root that carries a shadow token exactly
// when shadow is set. It is derived from the scope, so it never drifts from what the dispatch was
// granted. "" when there is none, when no findings root is configured, or when more than one
// prefix qualifies for the lane (ambiguous: the caller skips the check rather than guess).
func (p Profile) FindingsPrefix(shadow bool) string {
	if p.findingsRoot == "" {
		return ""
	}
	var match string
	for _, prefix := range p.PathScope.WritablePrefixes {
		if prefix == p.findingsRoot || !pathscope.Within(prefix, []string{p.findingsRoot}) {
			continue
		}
		if pathscope.ShadowMarked(strings.TrimPrefix(prefix, p.findingsRoot)) != shadow {
			continue
		}
		if match != "" {
			return ""
		}
		match = prefix
	}
	return match
}

// GrantOwner is what this profile's grants are rendered against for one lane: its agent key and
// scope bound every key a catalog kind marks profile-scoped (grants.ProfileScope).
func (p Profile) GrantOwner(shadow bool) grants.Owner {
	return grants.Owner{
		AgentKey:         p.AgentKey,
		Shadow:           shadow,
		WritablePrefixes: slices.Clone(p.PathScope.WritablePrefixes),
		ReadablePrefixes: slices.Clone(p.PathScope.ReadablePrefixes),
	}
}

// ErrProfileNotFound: no profile is registered for the agent key.
var ErrProfileNotFound = errors.New("no profile registered for this agent key")

// revisionOf is a short, stable identifier of content: the first 12 hex characters of its
// sha256. It answers "did this change between two runs"; it is not a security boundary.
func revisionOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:12]
}

// Registry is the loaded profiles, by agent key.
type Registry struct {
	profiles map[string]*Profile
}

// LoadOptions tune LoadRegistry. Zones is required; the zero value of every other field accepts
// only profiles that use no extension keys and no prompt_context files, state files or facts
// commands.
type LoadOptions struct {
	// Zones are the controller's scope zones (pathscope.NewZones): every path_scope entry is
	// checked against them, an agent key they reserve is refused, and findings prefixes are
	// derived under their findings root.
	Zones pathscope.Zones
	// Extensions are the extra top-level profile keys to accept, each with how it is checked.
	// Every other unknown key is an error.
	Extensions []Extension
	// PromptDir is the one directory prompt_context's text files are read from. Empty: a profile
	// may not name any such file.
	PromptDir string
	// StateFiles are the absolute state files a profile's prompt_context may name. Empty: none.
	StateFiles []string
	// FactsCommands is the catalog a profile's prompt_context.facts names an entry of. Empty: no
	// profile may run a facts command.
	FactsCommands map[string]FactsCommand
	// CursorTemplate is the one shape a prompt_context.cursor_file may take. Zero:
	// DefaultCursorTemplate.
	CursorTemplate CursorTemplate
}

// Extension is one deployment-specific top-level profile key. Exactly one of Schema and Opaque
// says how the loader checks a present key: validated against Schema (data from the controller
// config), or Opaque: carried unchecked for the deployment's own tooling to decode.
type Extension struct {
	Name   string
	Schema *Schema
	Opaque bool
}

func (e Extension) check(p Profile) error {
	node := p.Extensions[e.Name]
	if e.Schema == nil {
		// opaque: carried unchecked, but never as anchors and aliases (a recursive alias or an
		// alias bomb would be expanded by every copy and every decode) and never past the depth
		// bound
		if err := plainYAML(&node, "profile extension "+e.Name, false); err != nil {
			return err
		}
		return nil
	}
	if err := e.Schema.Validate(&node); err != nil {
		return fmt.Errorf("profile extension %s: %w", e.Name, err)
	}
	return nil
}

// LoadRegistry reads every *.yaml file in dir as one Profile, keyed by its own agent_key (not the
// file name). Decoding is strict: a key the Profile does not define, at any level, fails the load,
// except top-level keys named in opts.Extensions. Two files with one agent_key is a configuration
// error, never a silent override.
func LoadRegistry(dir string, opts LoadOptions) (*Registry, error) {
	if !opts.Zones.Validated() {
		return nil, fmt.Errorf("profiles: the scope zones were not validated (pathscope.NewZones)")
	}
	allowed := make(map[string]Extension, len(opts.Extensions))
	for _, e := range opts.Extensions {
		if e.Name == "" {
			return nil, fmt.Errorf("profile extensions: empty name")
		}
		if (e.Schema != nil) == e.Opaque {
			return nil, fmt.Errorf("profile extension %s: needs exactly one of a schema or opaque", e.Name)
		}
		if _, dup := allowed[e.Name]; dup {
			return nil, fmt.Errorf("profile extension %s: listed twice", e.Name)
		}
		if knownKey(e.Name) {
			return nil, fmt.Errorf("profile extension %s: the loader defines that key itself", e.Name)
		}
		allowed[e.Name] = e
	}
	penv, err := newPromptEnv(opts)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read profile dir %s: %w", dir, err)
	}
	reg := &Registry{profiles: make(map[string]*Profile)}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		full := filepath.Join(dir, entry.Name())
		data, err := grants.ReadConfigFile(full, MaxProfileBytes)
		if err != nil {
			return nil, fmt.Errorf("read profile file %s: %w", full, err)
		}
		p, err := decodeProfile(data, allowed)
		if err != nil {
			return nil, fmt.Errorf("parse profile file %s: %w", full, err)
		}
		if err := p.check(opts.Zones); err != nil {
			return nil, fmt.Errorf("profile file %s: %w", full, err)
		}
		if _, exists := reg.profiles[p.AgentKey]; exists {
			return nil, fmt.Errorf("duplicate agent_key %q across profile files (last seen in %s)", p.AgentKey, full)
		}
		if p.InjectOwnState {
			p.PromptContext.OwnState = true
			if p.PromptContext.StateFile == "" {
				return nil, fmt.Errorf("profile file %s: inject_own_state needs prompt_context.state_file", full)
			}
		}
		extra, err := p.PromptContext.resolve(penv, p.AgentKey)
		if err != nil {
			return nil, fmt.Errorf("profile file %s: %w", full, err)
		}
		// Files the profile pulls in are part of what it is: an edited appendix is a new revision.
		p.Revision = revisionOf(append(data, extra...))
		p.findingsRoot = opts.Zones.FindingsRoot
		reg.profiles[p.AgentKey] = &p
	}
	// A cursor_file is one agent's own store; a profile that names another's state_file would read
	// a shared multi-agent state file as its own (and the other way round).
	for _, p := range reg.profiles {
		for _, q := range reg.profiles {
			if f := p.PromptContext.CursorFile; f != "" && f == q.PromptContext.StateFile {
				return nil, fmt.Errorf("profile %s: prompt_context.cursor_file %q is profile %s's state_file", p.AgentKey, f, q.AgentKey)
			}
		}
	}
	return reg, nil
}

// check holds a decoded profile to the rules that need no file: its agent key, its scope against
// the zones and its grants' lanes.
func (p Profile) check(zones pathscope.Zones) error {
	switch {
	case p.AgentKey == "":
		return fmt.Errorf("no agent_key")
	case !agentKeyRe.MatchString(p.AgentKey):
		return fmt.Errorf("agent_key %q is not a plain name (%s)", p.AgentKey, agentKeyRe)
	case zones.ReservedName(p.AgentKey):
		return fmt.Errorf("agent_key %q is reserved by the scope zones (reserved_names)", p.AgentKey)
	case p.MaxAttempts < 0:
		return fmt.Errorf("max_attempts %d is negative", p.MaxAttempts)
	case p.BackendAffinity.MinContext < 0:
		return fmt.Errorf("backend_affinity.min_context %d is negative", p.BackendAffinity.MinContext)
	}
	if _, err := zones.NewScope(p.PathScope.WritablePrefixes, p.PathScope.ReadablePrefixes); err != nil {
		return fmt.Errorf("path_scope: %w", err)
	}
	return p.Grants.Validate()
}

// knownKey reports whether name is one of Profile's own top-level keys.
func knownKey(name string) bool {
	t := reflectProfileKeys()
	return slices.Contains(t, name)
}

// decodeProfile decodes one profile file strictly; unknown top-level keys land in Extensions,
// must be in allowed, and are checked as each Extension says.
func decodeProfile(data []byte, allowed map[string]Extension) (Profile, error) {
	var p Profile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil && !errors.Is(err, io.EOF) {
		return Profile{}, err
	}
	var unknown []string
	for name := range p.Extensions {
		if _, ok := allowed[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return Profile{}, fmt.Errorf("unknown profile key(s) %s (a deployment-specific key must be listed in the controller's profile_extensions)", strings.Join(unknown, ", "))
	}
	names := make([]string, 0, len(p.Extensions))
	for name := range p.Extensions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := allowed[name].check(p); err != nil {
			return Profile{}, err
		}
	}
	return p, nil
}

// DecodeExtension decodes the extension key name into out, strictly (an unknown field inside it
// is an error). It reports false, with out untouched, when the profile does not carry the key.
func (p Profile) DecodeExtension(name string, out any) (bool, error) {
	node, ok := p.Extensions[name]
	if !ok {
		return false, nil
	}
	raw, err := yaml.Marshal(&node)
	if err != nil {
		return true, fmt.Errorf("profile %s: extension %s: %w", p.AgentKey, name, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil && !errors.Is(err, io.EOF) {
		return true, fmt.Errorf("profile %s: extension %s: %w", p.AgentKey, name, err)
	}
	return true, nil
}

// Resolve looks up the profile for agentKey. It fails closed: an unknown key returns
// ErrProfileNotFound, never a default or wildcard profile. It returns an independent copy, so a
// caller changing the result never changes the registry or a later Resolve.
func (r *Registry) Resolve(agentKey string) (*Profile, error) {
	p, ok := r.profiles[agentKey]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrProfileNotFound, clip(agentKey))
	}
	cp := *p
	cp.AllowedTools = slices.Clone(p.AllowedTools)
	cp.PathScope.WritablePrefixes = slices.Clone(p.PathScope.WritablePrefixes)
	cp.PathScope.ReadablePrefixes = slices.Clone(p.PathScope.ReadablePrefixes)
	cp.BackendAffinity.RequireTags = slices.Clone(p.BackendAffinity.RequireTags)
	cp.BackendAffinity.ExcludeBackends = slices.Clone(p.BackendAffinity.ExcludeBackends)
	if p.Extensions != nil {
		cp.Extensions = make(map[string]yaml.Node, len(p.Extensions))
		for k, v := range p.Extensions {
			cp.Extensions[k] = *deepCopy(&v)
		}
	}
	cp.PromptContext = p.PromptContext.clone()
	cp.Grants = p.Grants.Clone()
	return &cp, nil
}

// All returns every loaded profile, each copied as Resolve copies it, sorted by agent key.
func (r *Registry) All() []*Profile {
	keys := make([]string, 0, len(r.profiles))
	for k := range r.profiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*Profile, 0, len(keys))
	for _, k := range keys {
		p, _ := r.Resolve(k) // k came from the map: never ErrProfileNotFound
		out = append(out, p)
	}
	return out
}

// CheckGrants renders both lanes of every profile's grants against the catalog, as a dispatch
// would, and returns every refusal: a controller checks this at start and on reload, so a
// profile whose grants the catalog refuses never waits for its first job to fail.
func (r *Registry) CheckGrants(cat *grants.Catalog) error {
	var errs []error
	for _, p := range r.All() {
		for _, shadow := range []bool{false, true} {
			if _, err := cat.Render(p.Grants.Lane(shadow), p.GrantOwner(shadow)); err != nil {
				errs = append(errs, fmt.Errorf("profile %s (%s lane): %w", p.AgentKey, map[bool]string{false: "real", true: "shadow"}[shadow], err))
			}
		}
	}
	return errors.Join(errs...)
}

// deepCopy copies a YAML node and everything under it, so a caller changing a resolved profile's
// extension never changes the registry's.
//
// Each node is copied once: an alias points at the copy of its anchor, so a node graph with a
// cycle (which the loader refuses, but a value built another way may hold) is copied without
// recursing into it again.
func deepCopy(n *yaml.Node) *yaml.Node { return copyNode(n, map[*yaml.Node]*yaml.Node{}) }

func copyNode(n *yaml.Node, done map[*yaml.Node]*yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	if cp, ok := done[n]; ok {
		return cp
	}
	cp := &yaml.Node{}
	done[n] = cp
	*cp = *n
	cp.Alias = copyNode(n.Alias, done)
	cp.Content = make([]*yaml.Node, len(n.Content))
	for i, c := range n.Content {
		cp.Content[i] = copyNode(c, done)
	}
	return cp
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
