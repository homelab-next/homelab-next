// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/homelab-next/homelab-next/orchestrator/internal/pathscope"
)

// A Rename is one old key and the key that replaces it. Old and New are dotted paths from the top
// of the configuration; "backends.*" stands for each backend (local, local_fallback, cloud and
// every additional entry). Convert, when set, rewrites the value too.
type Rename struct {
	Old, New string
	Convert  func(*yaml.Node) (*yaml.Node, error)
	Note     string
}

// Renames are the private controller's keys that take names naming no product, in the order a
// migration applies them. docs/orchestration-controller.md prints the same table; a test holds
// the two equal.
var Renames = []Rename{
	{Old: "hermes_local_home", New: "backends.local.home"},                   // scrub-allow: config key paths, not host names
	{Old: "hermes_local_fallback_home", New: "backends.local_fallback.home"}, // scrub-allow: config key paths, not host names
	{Old: "hermes_cloud_home", New: "backends.cloud.home"},                   // scrub-allow: config key paths, not host names
	{Old: "backends.*.hermes_home", New: "backends.*.home"},
	{Old: "hermes_agent_timeout_seconds", New: "runner.timeout_seconds"},
	{Old: "hermes_agent_job_timeout_seconds", New: "runner.job_timeout_seconds"},
	{Old: "hermes_agent_stall_timeout_seconds", New: "runner.stall_timeout_seconds"},
	{Old: "hermes_agent_stall_poll_interval_seconds", New: "runner.stall_poll_interval_seconds"},
	{Old: "hermes_agent_liveness", New: "runner.liveness"},
	{Old: "hermes_agent_max_turns", New: "runner.max_turns"},
	{Old: "hermes_agent_run_dir_base", New: "runner.run_dir_base"},
	{Old: "hermes_agent_env_allowlist", New: "runner.env_allowlist"},
	{Old: "hermes_agent_job_home_root", New: "runner.job_home_root"},
	{Old: "hermes_agent_interlock_wait_timeout_seconds", New: "interlock_wait_timeout_seconds"},
	{Old: "hermes_agent_grants_catalog", New: "grants_catalog"},
	{Old: "backends.*.base_url", New: "backends.*.endpoint", Convert: baseURLToEndpoint, Note: "the URL's host:port, a probe only"},
	{Old: "backend_status_script", New: "backend_status_command", Convert: scriptToCommand, Note: "[python3, <script>, --json]"},
}

// Dropped are the keys of what was not ported: the HTTP passthrough (ADR-0026's amendment). The
// gateway serves every caller that is not an agent job, and a job naming an unknown agent_key is
// always refused. Loading refuses each of them; a migration removes them.
var Dropped = map[string]string{
	"passthrough_enabled":          "the HTTP passthrough is not ported: call the gateway",
	"reject_unknown_agent_keys":    "an unknown agent_key is always refused (404)",
	"backends.*.api_key_env":       "the controller sends no request to a backend (the passthrough is not ported)",
	"backends.*.openai_compatible": "the passthrough's cloud leg is not ported",
}

// droppedKeys are Dropped's keys, sorted.
func droppedKeys() []string {
	out := make([]string, 0, len(Dropped))
	for k := range Dropped {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// baseURLToEndpoint keeps a base URL's host:port, with the scheme's default port when none is
// written.
// An empty base_url (a backend the private controller left unset) becomes no endpoint at all: nil.
// An error never quotes the URL, which may carry a password.
func baseURLToEndpoint(n *yaml.Node) (*yaml.Node, error) {
	if n.Kind == yaml.ScalarNode && n.Value == "" {
		return nil, nil
	}
	u, err := url.Parse(n.Value)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("base_url: not an http(s) URL with a host")
	}
	host := u.Host
	if u.Port() == "" {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		host = net.JoinHostPort(u.Hostname(), port)
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: host}, nil
}

// scriptToCommand turns the status script's path into the argv the private controller ran.
func scriptToCommand(n *yaml.Node) (*yaml.Node, error) {
	if n.Kind != yaml.ScalarNode || n.Value == "" {
		return nil, fmt.Errorf("backend_status_script: want a path")
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
	for _, v := range []string{"python3", n.Value, "--json"} {
		seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v})
	}
	return seq, nil
}

// MigrateOptions add what a migration cannot read from the old configuration.
type MigrateOptions struct {
	// ExtraRenames are a site's own old key names and the keys they become (SiteRenames, from
	// LoadSiteRenames), applied after Renames: names this repository does not spell.
	ExtraRenames SiteRenames
	// Scope is the tree's zones, written as the scope block when the configuration has none
	// (the private controller hard-coded them, so an old configuration never does). A
	// configuration that has a scope block and is given one is refused.
	Scope *pathscope.Zones
	// EngineMetrics are the site's engine metric names (LoadEngineMetrics, from the site's own
	// file), written as the engine_metrics block when the configuration has none: the private
	// controller had its engine's names built in, so an old configuration never names them. A
	// configuration that has the block and is given one is refused. Without it, a configuration
	// whose backends have load probes migrates with a note saying the controller will refuse them.
	EngineMetrics *EngineMetrics
}

// Migrate rewrites a configuration to the keys this controller reads: every old key under its
// new name, every dropped key removed, the scope block added from opts, comments kept. It returns
// the rewritten file and one note per change. A configuration that sets an old key and its new
// key is refused, and so is one whose result would not load (checked whether or not anything
// changed); a configuration that needs no change comes back unchanged.
func Migrate(data []byte) ([]byte, []string, error) { return MigrateWith(data, MigrateOptions{}) }

// MigrateWith is Migrate with what the old configuration cannot say (MigrateOptions).
func MigrateWith(data []byte, opts MigrateOptions) ([]byte, []string, error) {
	doc, err := parseNode(data)
	if err != nil {
		return nil, nil, err
	}
	extra, err := opts.ExtraRenames.renames()
	if err != nil {
		return nil, nil, err
	}
	notes, private, err := migrateNode(doc, true, extra)
	if err != nil {
		return nil, nil, err
	}
	if private {
		// a configuration in the private controller's keys: that controller built its local
		// backend with the interlock off whatever the file said, and here unset means on
		if local := lookup(lookup(doc.Content[0], "backends"), "local"); local != nil && local.Kind == yaml.MappingNode && lookup(local, "needs_interlock") == nil {
			local.Content = append(local.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "needs_interlock"},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"})
			notes = append(notes, "set backends.local.needs_interlock: false (the private controller never took the interlock for its local backend)") // scrub-allow: a config key path, not a host name
		}
		// that controller served without a token unless api_auth.enabled said true; here unset
		// means on
		if auth := lookup(doc.Content[0], "api_auth"); auth == nil {
			doc.Content[0].Content = append(doc.Content[0].Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "api_auth"},
				&yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Style: yaml.FlowStyle, Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Tag: "!!str", Value: "enabled"}, {Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"}}})
			notes = append(notes, "added api_auth: {enabled: false} (the private controller served without a token; here authentication is on unless it says false, and an API without it binds loopback only)")
		} else if auth.Kind == yaml.MappingNode && lookup(auth, "enabled") == nil {
			auth.Content = append(auth.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "enabled"}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"})
			notes = append(notes, "set api_auth.enabled: false (the private controller's default; here authentication is on unless it says false)")
		}
	}
	if opts.Scope != nil {
		if lookup(doc.Content[0], "scope") != nil {
			return nil, nil, fmt.Errorf("scope: the configuration has a scope block; give the migration none")
		}
		if err := addScope(doc.Content[0], *opts.Scope); err != nil {
			return nil, nil, err
		}
		notes = append(notes, "added the scope block")
	}
	if opts.EngineMetrics != nil {
		if lookup(doc.Content[0], "engine_metrics") != nil {
			return nil, nil, fmt.Errorf("engine_metrics: the configuration has the block; give the migration none")
		}
		if opts.EngineMetrics.IsZero() {
			return nil, nil, fmt.Errorf("engine_metrics: the migration was given an empty set")
		}
		if err := opts.EngineMetrics.Check(); err != nil {
			return nil, nil, err
		}
		var n yaml.Node
		if err := n.Encode(*opts.EngineMetrics); err != nil {
			return nil, nil, err
		}
		doc.Content[0].Content = append(doc.Content[0].Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "engine_metrics"}, &n)
		notes = append(notes, "added the engine_metrics block")
	} else if private && anyLoadProbes(doc.Content[0]) && lookup(doc.Content[0], "engine_metrics") == nil {
		notes = append(notes, "a backend has load_probe_urls but the configuration names no engine_metrics: the controller refuses to start until it does (give the migration the site's engine metrics file)")
	}
	if len(notes) == 0 {
		if _, err := ParseWith(data, ParseOptions{ExtraRenames: opts.ExtraRenames}); err != nil {
			return nil, nil, fmt.Errorf("the configuration does not load: %w", err)
		}
		return data, nil, nil
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, nil, err
	}
	if _, err := ParseWith(buf.Bytes(), ParseOptions{ExtraRenames: opts.ExtraRenames}); err != nil {
		return nil, notes, fmt.Errorf("the migrated configuration does not load: %w", err)
	}
	return buf.Bytes(), notes, nil
}

// addScope appends a scope block holding every key of z, so none is left to a default.
func addScope(root *yaml.Node, z pathscope.Zones) error {
	block := struct {
		DeniedRoots        []string `yaml:"denied_roots"`
		FindingsRoot       string   `yaml:"findings_root"`
		SharedWrite        []string `yaml:"shared_write"`
		ReservedNames      []string `yaml:"reserved_names"`
		AllowNoDeniedRoots bool     `yaml:"allow_no_denied_roots,omitempty"`
	}{z.DeniedRoots, z.FindingsRoot, z.SharedWrite, z.ReservedNames, z.AllowNoDeniedRoots}
	for _, l := range []*[]string{&block.DeniedRoots, &block.SharedWrite, &block.ReservedNames} {
		if *l == nil {
			*l = []string{}
		}
	}
	var n yaml.Node
	if err := n.Encode(block); err != nil {
		return err
	}
	root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "scope"}, &n)
	return nil
}

// migrateNode applies Renames and Dropped to doc in place. Loading (rewrite false) refuses a
// dropped key; a migration removes it.
// The second result reports whether a built-in rename fired: the configuration was written in
// the private controller's keys (a site rename or a dropped key alone does not say so).
func migrateNode(doc *yaml.Node, rewrite bool, extra []Rename) ([]string, bool, error) {
	root := doc.Content[0]
	var notes []string
	for _, at := range expand(root, "") {
		for _, key := range droppedKeys() {
			why := Dropped[key]
			if !matchPath(key, at.path) {
				continue
			}
			if lookup(at.node, at.key) == nil {
				continue
			}
			if !rewrite {
				return nil, false, fmt.Errorf("%s: %s (remove it, or rewrite the configuration with the migration)", at.path, why)
			}
			remove(at.node, at.key)
			notes = append(notes, fmt.Sprintf("removed %s: %s", at.path, why))
		}
	}
	builtin := false
	for i, r := range append(slices.Clone(Renames), extra...) {
		for _, at := range expand(root, r.Old) {
			val := lookup(at.node, at.key)
			if val == nil {
				continue
			}
			newPath := strings.Replace(r.New, "*", at.star, 1)
			parent, leaf, err := ensure(root, newPath)
			if err != nil {
				return nil, false, err
			}
			if lookup(parent, leaf) != nil {
				return nil, false, fmt.Errorf("%s and %s are both set: they are one setting (keep %s)", at.path, newPath, newPath)
			}
			if r.Convert != nil {
				conv, err := r.Convert(val)
				if err != nil {
					return nil, false, fmt.Errorf("%s: %w", at.path, err)
				}
				if conv == nil {
					removeKey(at.node, at.key)
					notes = append(notes, fmt.Sprintf("removed %s: empty, so no %s", at.path, newPath))
					builtin = builtin || i < len(Renames)
					continue
				}
				conv.HeadComment, conv.LineComment = val.HeadComment, val.LineComment
				val = conv
			}
			keyNode := removeKey(at.node, at.key)
			keyNode.Value = leaf
			parent.Content = append(parent.Content, keyNode, val)
			verb := "read %s as %s"
			if rewrite {
				verb = "renamed %s to %s"
			}
			note := fmt.Sprintf(verb, at.path, newPath)
			if r.Note != "" {
				note += " (" + r.Note + ")"
			}
			notes = append(notes, note)
			builtin = builtin || i < len(Renames)
		}
	}
	return notes, builtin, nil
}

// site is one place an old key may sit: its mapping, its key and its full path; star is what "*"
// matched (a backend's path segment).
type site struct {
	node      *yaml.Node
	key, path string
	star      string
}

// expand lists the sites of a dotted pattern ("" lists every key of the top level and of every
// backend, which is where a dropped key may sit).
func expand(root *yaml.Node, pattern string) []site {
	if pattern == "" {
		var out []site
		for i := 0; i+1 < len(root.Content); i += 2 {
			k := root.Content[i].Value
			out = append(out, site{root, k, k, ""})
		}
		for _, b := range backendNodes(root) {
			for i := 0; i+1 < len(b.node.Content); i += 2 {
				k := b.node.Content[i].Value
				out = append(out, site{b.node, k, b.path + "." + k, b.star})
			}
		}
		return out
	}
	if rest, ok := strings.CutPrefix(pattern, "backends.*."); ok {
		var out []site
		for _, b := range backendNodes(root) {
			out = append(out, site{b.node, rest, b.path + "." + rest, b.star})
		}
		return out
	}
	return []site{{root, pattern, pattern, ""}}
}

type backendNode struct {
	node       *yaml.Node
	path, star string
}

// backendNodes are the backend mappings: local, local_fallback, cloud and each additional entry.
func backendNodes(root *yaml.Node) []backendNode {
	b := lookup(root, "backends")
	if b == nil || b.Kind != yaml.MappingNode {
		return nil
	}
	var out []backendNode
	for _, name := range []string{"local", "local_fallback", "cloud"} {
		if n := lookup(b, name); n != nil && n.Kind == yaml.MappingNode {
			out = append(out, backendNode{n, "backends." + name, name})
		}
	}
	if add := lookup(b, "additional"); add != nil && add.Kind == yaml.SequenceNode {
		for i, n := range add.Content {
			if n.Kind == yaml.MappingNode {
				star := fmt.Sprintf("additional[%d]", i)
				out = append(out, backendNode{n, "backends." + star, star})
			}
		}
	}
	return out
}

// matchPath reports whether a Dropped key names path.
func matchPath(pattern, path string) bool {
	if pattern == path {
		return true
	}
	rest, ok := strings.CutPrefix(pattern, "backends.*.")
	if !ok {
		return false
	}
	head, leaf, ok := cutLast(path)
	return ok && leaf == rest && strings.HasPrefix(head, "backends.") && !strings.Contains(strings.TrimPrefix(head, "backends."), ".")
}

func cutLast(path string) (string, string, bool) {
	i := strings.LastIndexByte(path, '.')
	if i < 0 {
		return "", path, false
	}
	return path[:i], path[i+1:], true
}

// ensure returns the mapping that holds the last segment of a new path ("a.b.c": a.b) and that
// segment, creating the mappings on the way. A segment "additional[i]" is that entry of
// backends.additional.
func ensure(root *yaml.Node, path string) (*yaml.Node, string, error) {
	parts := strings.Split(path, ".")
	n := root
	for _, p := range parts[:len(parts)-1] {
		if name, idx, ok := strings.Cut(p, "["); ok {
			list := lookup(n, name)
			var i int
			if _, err := fmt.Sscanf(idx, "%d]", &i); err != nil || list == nil || list.Kind != yaml.SequenceNode || i >= len(list.Content) {
				return nil, "", fmt.Errorf("%s: no such entry", path)
			}
			n = list.Content[i]
			continue
		}
		next := lookup(n, p)
		if next == nil {
			next = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: p}, next)
		}
		if next.Kind != yaml.MappingNode {
			return nil, "", fmt.Errorf("%s: %s is not a mapping", path, p)
		}
		n = next
	}
	return n, parts[len(parts)-1], nil
}

// lookup returns the value of key in mapping n, or nil.
func lookup(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// removeKey removes key from mapping n and returns its key node.
func removeKey(n *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			k := n.Content[i]
			n.Content = append(n.Content[:i], n.Content[i+2:]...)
			return k
		}
	}
	return nil
}

func remove(n *yaml.Node, key string) { removeKey(n, key) }
