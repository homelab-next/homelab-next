// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/homelab-next/homelab-next/orchestrator/internal/grants"
	"github.com/homelab-next/homelab-next/orchestrator/internal/pathscope"
)

// testZones is a fictional tree: owner/ is never writable, findings live under notes/findings/,
// every lane writes inbox/, and no agent may run as operator.
var testZones = func() pathscope.Zones {
	z, err := pathscope.NewZones(pathscope.Zones{
		DeniedRoots:   []string{"owner"},
		FindingsRoot:  "notes/findings/",
		SharedWrite:   []string{"inbox/"},
		ReservedNames: []string{"operator"},
	})
	if err != nil {
		panic(err)
	}
	return z
}()

// plainOptions is a load with the zones and nothing else.
func plainOptions() LoadOptions { return LoadOptions{Zones: testZones} }

const testProfileYAML = `
id: test-profile-v1
agent_key: test-agent
allowed_tools: ["notes_query", "notes_write"]
path_scope:
  writable_prefixes: ["notes/findings/test/", "inbox/"]
  readable_prefixes: ["owner/approved/", "owner/denied/"]
`

func writeProfileFile(t *testing.T, dir, filename, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0o600); err != nil {
		t.Fatalf("write profile file: %v", err)
	}
}

func loadOne(t *testing.T, body string) (*Registry, error) {
	t.Helper()
	dir := t.TempDir()
	writeProfileFile(t, dir, "p.yaml", body)
	return LoadRegistry(dir, plainOptions())
}

func TestLoadRegistry_ResolveKnownAgentReturnsFullProfile(t *testing.T) {
	reg, err := loadOne(t, testProfileYAML)
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.Resolve("test-agent")
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "test-profile-v1" || p.AgentKey != "test-agent" || len(p.AllowedTools) != 2 || p.AllowedTools[0] != "notes_query" {
		t.Errorf("profile = %+v", p)
	}
	if len(p.PathScope.WritablePrefixes) != 2 || len(p.Extensions) != 0 {
		t.Errorf("scope %v, extensions %v", p.PathScope, p.Extensions)
	}
	if all := reg.All(); len(all) != 1 || all[0].AgentKey != "test-agent" {
		t.Errorf("All = %v", all)
	}
}

func TestLoadRegistry_NeedsValidatedZones(t *testing.T) {
	dir := t.TempDir()
	writeProfileFile(t, dir, "p.yaml", testProfileYAML)
	if _, err := LoadRegistry(dir, LoadOptions{}); err == nil {
		t.Fatal("a load without validated zones succeeded")
	}
}

func TestResolve_UnknownAgentKeyFailsClosed(t *testing.T) {
	reg, err := loadOne(t, testProfileYAML)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Resolve("never-registered-agent"); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("Resolve(unknown) err = %v, want ErrProfileNotFound", err)
	}
}

func TestResolve_ReturnsACopyNotTheRegistrysOwnPointer(t *testing.T) {
	reg, err := loadOne(t, testProfileYAML+"backend_affinity: {require_tags: [a]}\ngrants:\n  real: [{name: n, kind: k, env: {A: b}}]\n  shadow: [{name: n, kind: k}]\n")
	if err != nil {
		t.Fatal(err)
	}
	p1, _ := reg.Resolve("test-agent")
	p1.AllowedTools[0] = "mutated"
	p1.PathScope.WritablePrefixes[0] = "mutated"
	p1.BackendAffinity.RequireTags[0] = "mutated"
	p1.Grants.Real[0].Env["A"] = "mutated"
	p2, _ := reg.Resolve("test-agent")
	if p2.AllowedTools[0] == "mutated" || p2.PathScope.WritablePrefixes[0] == "mutated" ||
		p2.BackendAffinity.RequireTags[0] == "mutated" || p2.Grants.Real[0].Env["A"] == "mutated" {
		t.Fatal("mutating a resolved profile affected a later Resolve: Resolve must return an independent copy")
	}
}

func TestLoadRegistry_DuplicateAgentKeyAcrossFilesIsAnError(t *testing.T) {
	dir := t.TempDir()
	writeProfileFile(t, dir, "a.yaml", testProfileYAML)
	writeProfileFile(t, dir, "b.yaml", testProfileYAML)
	if _, err := LoadRegistry(dir, plainOptions()); err == nil {
		t.Fatal("two profile files with one agent_key loaded")
	}
}

// The revision is a content hash: the same bytes give the same revision, other bytes another.
func TestLoadRegistry_RevisionIsAContentHash(t *testing.T) {
	rev := func(body string) string {
		reg, err := loadOne(t, body)
		if err != nil {
			t.Fatal(err)
		}
		p, _ := reg.Resolve("test-agent")
		return p.Revision
	}
	a, b := rev(testProfileYAML), rev(testProfileYAML)
	if a == "" || a != b {
		t.Fatalf("revisions %q and %q for identical content", a, b)
	}
	if c := rev(testProfileYAML + "\n# a trailing comment\n"); c == a {
		t.Errorf("revision unchanged after the file's content changed")
	}
}

// FindingsPrefix derives a lane's findings directory from the scope, under the zones' findings
// root, and fails closed on ambiguity.
func TestFindingsPrefix(t *testing.T) {
	for _, tc := range []struct {
		name     string
		writable []string
		shadow   bool
		want     string
	}{
		{"real prefix present, no shadow entry", []string{"notes/findings/test/", "inbox/"}, false, "notes/findings/test/"},
		{"shadow requested but none", []string{"notes/findings/test/", "inbox/"}, true, ""},
		{"real of a pair", []string{"notes/findings/x/", "notes/findings/x-shadow/", "inbox/"}, false, "notes/findings/x/"},
		{"shadow of a pair", []string{"notes/findings/x/", "notes/findings/x-shadow/", "inbox/"}, true, "notes/findings/x-shadow/"},
		{"no findings prefix at all", []string{"inbox/"}, false, ""},
		{"ambiguous: two real candidates", []string{"notes/findings/one/", "notes/findings/two/", "inbox/"}, false, ""},
		{"other prefixes never match", []string{"notes/state/x/", "notes/state/x-shadow/", "inbox/"}, false, ""},
		{"the findings root itself is no agent's", []string{"notes/findings/"}, false, ""},
		{"a real prefix is not the shadow lane's", []string{"notes/findings/x/"}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Profile{PathScope: PathScope{WritablePrefixes: tc.writable}, findingsRoot: "notes/findings/"}
			if got := p.FindingsPrefix(tc.shadow); got != tc.want {
				t.Errorf("FindingsPrefix(%v) = %q, want %q", tc.shadow, got, tc.want)
			}
		})
	}
	if got := (Profile{PathScope: PathScope{WritablePrefixes: []string{"notes/findings/x/"}}}).FindingsPrefix(false); got != "" {
		t.Errorf("no findings root configured: %q", got)
	}
	reg, err := loadOne(t, testProfileYAML)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := reg.Resolve("test-agent"); p.FindingsPrefix(false) != "notes/findings/test/" {
		t.Errorf("a loaded profile's findings prefix: %q", p.FindingsPrefix(false))
	}
}

func TestLoadRegistry_BackendAffinityParses(t *testing.T) {
	reg, err := loadOne(t, testProfileYAML+"backend_affinity:\n  min_context: 1000000\n  exclusive: true\n  require_tags: [general]\n  exclude_backends: [engine-b]\nlocal_only: true\nmax_attempts: 2\n")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := reg.Resolve("test-agent")
	if a := p.BackendAffinity; !a.Exclusive || a.MinContext != 1000000 || a.RequireTags[0] != "general" || a.ExcludeBackends[0] != "engine-b" || !p.LocalOnly || p.MaxAttempts != 2 {
		t.Errorf("profile = %+v", p)
	}
	for _, bad := range []string{"max_attempts: -1\n", "backend_affinity: {min_context: -5}\n", "backend_affinity: {exclusiv: true}\n"} {
		if _, err := loadOne(t, testProfileYAML+bad); err == nil {
			t.Errorf("%q loaded", bad)
		}
	}
}

// The grants subtree is a permission: a typo'd lane or field must fail the load, a ${VAR} in a
// value must fail it, and so must a profile that grants one lane and not the other.
func TestLoadRegistry_GrantsAreStrict(t *testing.T) {
	base := "id: g-v1\nagent_key: g\n"
	for name, g := range map[string]string{
		"lane typo":  "grants:\n  reall: [{name: v, kind: notes}]\n  shadow: [{name: v, kind: notes}]\n",
		"field typo": "grants:\n  real: [{name: v, knd: notes}]\n  shadow: [{name: v, kind: notes}]\n",
		"env typo":   "grants:\n  real: [{name: v, kind: notes, evn: {A: /x}}]\n  shadow: [{name: v, kind: notes}]\n",
		"reference":  "grants:\n  real: [{name: v, kind: notes, env: {A: \"${SOME_CREDENTIAL}\"}}]\n  shadow: [{name: v, kind: notes}]\n",
		"one lane":   "grants:\n  real: [{name: v, kind: notes}]\n",
	} {
		if _, err := loadOne(t, base+g); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	reg, err := loadOne(t, base+"grants:\n  real: [{name: v, kind: notes, env: {A: b}, timeout: 5}]\n  shadow: [{name: v, kind: notes}]\n")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := reg.Resolve("g")
	if len(p.Grants.Real) != 1 || p.Grants.Real[0].Env["A"] != "b" || p.Grants.Real[0].Timeout != 5 || len(p.Grants.Shadow) != 1 {
		t.Errorf("grants decoded wrong: %+v", p.Grants)
	}
}

// The scope is what profile-bound grant keys are checked against, so it must itself be plain: no
// writable denied root (in any spelling), no "..", no absolute path, no root, nothing unclean.
func TestLoadRegistry_RefusesUnsafeScope(t *testing.T) {
	for _, scope := range []string{
		"writable_prefixes: [owner/approved/]",
		"writable_prefixes: [\"./Owner/\"]",
		"writable_prefixes: [notes/findings/a/../../../owner/]",
		"writable_prefixes: [/srv/notes/inbox/]",
		"writable_prefixes: [\".\"]",
		"readable_prefixes: [\"../outside/\"]",
		"readable_prefixes: [\" inbox/\"]",
		"writable_prefixes: [notes/./findings/x/]",
		"writable_prefixes: [notes//findings/x/]",
		"readable_prefixes: [notes/./findings/x/]",
		"readable_prefixes: [.git/]",
	} {
		if _, err := loadOne(t, "agent_key: watcher\npath_scope:\n  "+scope+"\n"); err == nil {
			t.Errorf("path_scope %s: loaded", scope)
		}
	}
	reg, err := loadOne(t, "agent_key: watcher\npath_scope:\n  writable_prefixes: [notes/findings/watch/, inbox/]\n  readable_prefixes: [owner/priorities.md, owner/approved/]\n")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := reg.Resolve("watcher")
	o := p.GrantOwner(true)
	if o.AgentKey != "watcher" || !o.Shadow || len(o.WritablePrefixes) != 2 || len(o.ReadablePrefixes) != 2 {
		t.Errorf("GrantOwner = %+v", o)
	}
}

// An agent key is a plain name, and never one the zones reserve.
func TestLoadRegistry_AgentKeys(t *testing.T) {
	for _, key := range []string{"operator", "operator-review", "Operator", "", "Bad_Key", "a/b", "a b", "-a", strings.Repeat("a", MaxAgentKeyLen+1)} {
		body := strings.Replace(testProfileYAML, "agent_key: test-agent", "agent_key: \""+key+"\"", 1)
		if _, err := loadOne(t, body); err == nil {
			t.Errorf("agent_key %q: loaded", key)
		}
	}
	for _, key := range []string{"operatorx", "watcher", "a_b-1", strings.Repeat("a", MaxAgentKeyLen)} {
		body := strings.Replace(testProfileYAML, "agent_key: test-agent", "agent_key: "+key, 1)
		if _, err := loadOne(t, body); err != nil {
			t.Errorf("agent_key %q: %v", key, err)
		}
	}
}

// CheckGrants renders every profile's two lanes against a catalog, so a profile the catalog
// refuses is found at load, not at its first job.
func TestCheckGrants(t *testing.T) {
	cat, err := grants.ParseCatalog([]byte("kinds:\n  notes:\n    command: /usr/local/bin/notes-mcp\n    allowed_env: [NOTES_MODE]\n    allowed_values: {NOTES_MODE: [read, write]}\n"), testZones)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := loadOne(t, "agent_key: g\ngrants:\n  real: [{name: n, kind: notes, env: {NOTES_MODE: write}}]\n  shadow: [{name: n, kind: notes, env: {NOTES_MODE: read}}]\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.CheckGrants(cat); err != nil {
		t.Fatal(err)
	}
	reg, err = loadOne(t, "agent_key: g\ngrants:\n  real: [{name: n, kind: notes}]\n  shadow: [{name: n, kind: notes, env: {NOTES_MODE: append}}]\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.CheckGrants(cat); !errors.Is(err, grants.ErrInvalid) || !strings.Contains(err.Error(), "shadow lane") {
		t.Fatalf("CheckGrants = %v", err)
	}
}

// The example profile the MCP render writes into (examples/mcp/clients/orchestrator) loads as a
// whole profile, and its grants render against the catalog the same render wrote.
func TestTheRenderedExampleProfileLoads(t *testing.T) {
	base := filepath.Join("..", "..", "..", "examples", "mcp", "clients", "orchestrator")
	reg, err := LoadRegistry(filepath.Join(base, "profiles"), plainOptions())
	if err != nil {
		t.Fatal(err)
	}
	cat, err := grants.LoadCatalog(filepath.Join(base, "mcp_catalog.yaml"), testZones)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.CheckGrants(cat); err != nil {
		t.Fatal(err)
	}
}

// A resolved profile's extension is the caller's own copy, down to its nodes.
func TestResolve_DeepCopiesExtensions(t *testing.T) {
	dir := t.TempDir()
	writeProfileFile(t, dir, "w.yaml", "agent_key: w\nquery_scope: {tables: [a]}\n")
	reg, err := LoadRegistry(dir, withExt(Extension{Name: "query_scope", Opaque: true}))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := reg.Resolve("w")
	n := p.Extensions["query_scope"]
	n.Content[1].Content[0].Value = "mutated"
	again, _ := reg.Resolve("w")
	if again.Extensions["query_scope"].Content[1].Content[0].Value != "a" {
		t.Fatal("changing a resolved extension's node changed the registry's")
	}
}

// A profile file is read without following a symbolic link and within a size bound.
func TestLoadRegistry_ReadsOnlyRegularBoundedFiles(t *testing.T) {
	src := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(src, []byte(testProfileYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(src, filepath.Join(dir, "p.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistry(dir, plainOptions()); err == nil {
		t.Error("a profile behind a symbolic link loaded")
	}
	if _, err := loadOne(t, testProfileYAML+"#"+strings.Repeat("x", MaxProfileBytes)+"\n"); err == nil {
		t.Error("an oversized profile loaded")
	}
	if got := clip(strings.Repeat("a", 79) + "éé"); !utf8.ValidString(got) {
		t.Errorf("clip cut a rune: %q", got)
	}
}

// An opaque extension holds no anchor or alias: a recursive alias would make every Resolve
// recurse without end (a stack overflow stops the controller), and an alias bomb would be
// expanded by every copy.
func TestLoadRegistry_OpaqueExtensionsHoldNoAliases(t *testing.T) {
	for name, body := range map[string]string{
		"recursive alias": "agent_key: w\nqx: &x [1, *x]\n",
		"alias bomb":      "agent_key: w\nqx:\n  a: &a [x, x, x, x, x, x, x, x, x]\n  b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n  c: [*b, *b, *b, *b, *b, *b, *b, *b, *b]\n",
		"anchor alone":    "agent_key: w\nqx: &x {a: 1}\n",
		"merge key":       "agent_key: w\nqx: {<<: {a: 1}}\n",
		"too deep":        "agent_key: w\nqx: " + strings.Repeat("[", 40) + strings.Repeat("]", 40) + "\n",
		"too many nodes":  "agent_key: w\nqx: [" + strings.Repeat("1, ", MaxNodes) + "1]\n",
	} {
		dir := t.TempDir()
		writeProfileFile(t, dir, "w.yaml", body)
		if _, err := LoadRegistry(dir, withExt(Extension{Name: "qx", Opaque: true})); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// deepCopy copies a cyclic node graph without recursing into the cycle. It runs in a child
// process, so a stack overflow (fatal, not a panic) fails this test instead of the whole run.
func TestDeepCopy_IsAliasSafe(t *testing.T) {
	if os.Getenv("PROFILE_DEEPCOPY_CHILD") == "1" {
		seq := &yaml.Node{Kind: yaml.SequenceNode, Anchor: "x"}
		seq.Content = []*yaml.Node{{Kind: yaml.ScalarNode, Value: "1"}, {Kind: yaml.AliasNode, Alias: seq}}
		cp := deepCopy(seq)
		if cp == seq || cp.Content[1].Alias != cp || cp.Content[0] == seq.Content[0] {
			os.Exit(3)
		}
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDeepCopy_IsAliasSafe$", "-test.count=1")
	cmd.Env = append(os.Environ(), "PROFILE_DEEPCOPY_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("deepCopy on a cyclic node did not return cleanly: %v\n%.400s", err, out)
	}
}
