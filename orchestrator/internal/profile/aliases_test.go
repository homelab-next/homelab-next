// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// legacyAliases is a fictional site's table: its old key names are the site's, never spelt here.
var legacyAliases = KeyAliases{"legacy_scope": "path_scope"}

func TestKeyAliases_LoadReadsTheOldKeyAndRefusesBoth(t *testing.T) {
	body := "agent_key: watcher\nlegacy_scope:\n  writable_prefixes: [notes/findings/watch/]\n"
	if _, err := loadOne(t, body); err == nil {
		t.Fatal("a site's old key loaded without its aliases")
	}
	dir := t.TempDir()
	writeProfileFile(t, dir, "w.yaml", body)
	opts := plainOptions()
	opts.KeyAliases = legacyAliases
	reg, err := LoadRegistry(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := reg.Resolve("watcher")
	if len(p.PathScope.WritablePrefixes) != 1 || len(reg.Notices()) != 1 || !strings.Contains(reg.Notices()[0], "read legacy_scope as path_scope (a site alias)") {
		t.Errorf("scope = %+v, notices %v", p.PathScope, reg.Notices())
	}
	if p.Revision != revisionOf([]byte(body)) {
		t.Error("the revision is not the file's own content")
	}
	// the scope is checked as path_scope is
	writeProfileFile(t, dir, "w.yaml", "agent_key: watcher\nlegacy_scope: {writable_prefixes: [owner/x/]}\n")
	if _, err := LoadRegistry(dir, opts); err == nil {
		t.Error("an aliased scope skipped the zones")
	}
	writeProfileFile(t, dir, "w.yaml", "agent_key: watcher\nlegacy_scope: {writable_prefixes: [a/]}\npath_scope: {writable_prefixes: [a/]}\n")
	if _, err := LoadRegistry(dir, opts); err == nil {
		t.Error("an old and a new name of one key loaded")
	}
}

func TestKeyAliases_Validate(t *testing.T) {
	for name, a := range KeyAliasesCases() {
		if err := a.Validate(); err == nil {
			t.Errorf("%s: validated", name)
		}
		dir := t.TempDir()
		writeProfileFile(t, dir, "w.yaml", "agent_key: w\n")
		opts := plainOptions()
		opts.KeyAliases = a
		if _, err := LoadRegistry(dir, opts); err == nil {
			t.Errorf("%s: a load accepted the table", name)
		}
	}
	dir := t.TempDir()
	writeProfileFile(t, dir, "w.yaml", "agent_key: w\n")
	opts := withExt(Extension{Name: "legacy_scope", Opaque: true})
	opts.KeyAliases = legacyAliases
	if _, err := LoadRegistry(dir, opts); err == nil {
		t.Error("an alias that is also an extension key loaded")
	}
	if a, err := ParseKeyAliases([]byte("legacy_scope: path_scope\n")); err != nil || a["legacy_scope"] != "path_scope" {
		t.Errorf("ParseKeyAliases = %v, %v", a, err)
	}
	for _, bad := range []string{"legacy_scope: path_scope\nlegacy_scope: toolsets\n", "- a\n", "legacy_scope: paths\n"} {
		if _, err := ParseKeyAliases([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func KeyAliasesCases() map[string]KeyAliases {
	return map[string]KeyAliases{
		"target not a key":      {"legacy_scope": "paths"},
		"old name is a key":     {"toolsets": "path_scope"},
		"identity target":       {"legacy_key": "agent_key"},
		"id target":             {"legacy_id": "id"},
		"permission target":     {"legacy_grants": "grants"},
		"tools target":          {"legacy_tools": "allowed_tools"},
		"prompt target":         {"legacy_prompt": "prompt_context"},
		"toolsets target":       {"legacy_toolsets": "toolsets"},
		"local-only target":     {"legacy_local": "local_only"},
		"not a plain name":      {"Legacy-Scope": "path_scope"},
		"dotted":                {"legacy.scope": "path_scope"},
		"a chain":               {"legacy_a": "legacy_b", "legacy_b": "path_scope"},
		"two names for one key": {"legacy_a": "path_scope", "legacy_b": "path_scope"},
	}
}

func TestMigrateDir_RewritesAProfilesDirectory(t *testing.T) {
	dir := t.TempDir()
	writeProfileFile(t, dir, "a.yaml", "# watcher\nagent_key: watcher\nlegacy_scope: # the scope\n  writable_prefixes: [notes/findings/watch/]\n")
	writeProfileFile(t, dir, "b.yaml", "agent_key: other\n")
	before, _ := os.ReadFile(filepath.Join(dir, "b.yaml"))
	notes, err := MigrateDir(dir, migrateOpts(legacyAliases))
	if err != nil || len(notes) != 1 || !strings.HasPrefix(notes[0], "a.yaml: ") {
		t.Fatalf("Migrate = %v, %v", notes, err)
	}
	a, _ := os.ReadFile(filepath.Join(dir, "a.yaml"))
	if strings.Contains(string(a), "legacy_scope") || !strings.Contains(string(a), "path_scope: # the scope") || !strings.HasPrefix(string(a), "# watcher\n") {
		t.Errorf("a.yaml:\n%s", a)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "b.yaml")); string(after) != string(before) {
		t.Error("a file with nothing to rename was rewritten")
	}
	if _, err := LoadRegistry(dir, plainOptions()); err != nil {
		t.Errorf("the migrated directory does not load without aliases: %v", err)
	}
	if again, err := MigrateDir(dir, migrateOpts(legacyAliases)); err != nil || len(again) != 0 {
		t.Errorf("a second migration: %v, %v", again, err)
	}
	// one file setting both stops the migration before any file is written
	writeProfileFile(t, dir, "c.yaml", "agent_key: c\nlegacy_scope: {}\n")
	writeProfileFile(t, dir, "d.yaml", "agent_key: d\nlegacy_scope: {}\npath_scope: {}\n")
	if _, err := MigrateDir(dir, migrateOpts(legacyAliases)); err == nil {
		t.Fatal("a profile with both names migrated")
	}
	if c, _ := os.ReadFile(filepath.Join(dir, "c.yaml")); !strings.Contains(string(c), "legacy_scope") {
		t.Error("a file was written before the refusal")
	}
	if _, err := MigrateDir(dir, migrateOpts(KeyAliases{"legacy_key": "agent_key"})); err == nil {
		t.Error("an invalid table migrated")
	}
}

func migrateOpts(a KeyAliases) LoadOptions {
	o := plainOptions()
	o.KeyAliases = a
	return o
}

// The rewrite never follows a symbolic link planted where a temporary file might go, keeps the
// file's own mode, refuses a profile that is a symbolic link, and writes nothing unless the whole
// migrated directory loads.
func TestMigrateDir_WritesSafelyAllOrNothing(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("untouched\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("agent_key: a\nlegacy_scope: {writable_prefixes: [notes/a/]}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.yaml.migrate", ".a.yaml.tmp"} { // the old temp name, a plausible one
		if err := os.Symlink(outside, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, ".a.yaml.0666"), nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateDir(dir, migrateOpts(legacyAliases)); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(outside); string(b) != "untouched\n" {
		t.Error("the migration wrote through a planted symbolic link")
	}
	fi, err := os.Stat(filepath.Join(dir, "a.yaml"))
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Errorf("mode after the migration = %v (%v), want 0640", fi.Mode().Perm(), err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".a.yaml.*")); len(left) != 2 {
		t.Errorf("temporary files left or planted ones touched: %v", left)
	}
	// a profile that is a symbolic link is refused, and nothing is written
	dir = t.TempDir()
	src := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(src, []byte("agent_key: p\nlegacy_scope: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(src, filepath.Join(dir, "p.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateDir(dir, migrateOpts(legacyAliases)); err == nil {
		t.Error("a profile behind a symbolic link migrated")
	}
	if b, _ := os.ReadFile(src); !strings.Contains(string(b), "legacy_scope") {
		t.Error("the link's target was rewritten")
	}
	// one migrated profile that would not load stops the whole migration before any write
	dir = t.TempDir()
	writeProfileFile(t, dir, "a.yaml", "agent_key: a\nlegacy_scope: {writable_prefixes: [notes/a/]}\n")
	writeProfileFile(t, dir, "b.yaml", "agent_key: b\nlegacy_scope: {writable_prefixes: [owner/x/]}\n")
	if _, err := MigrateDir(dir, migrateOpts(legacyAliases)); err == nil || !strings.Contains(err.Error(), "nothing written") {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "a.yaml")); !strings.Contains(string(b), "legacy_scope") {
		t.Error("a file was written before the refusal")
	}
}

// MigrateDir renames the key where it is written and keeps every other byte, so a profile the MCP
// render owns (its generated grants block) still matches the render after the migration.
func TestMigrateDir_KeepsEveryOtherByte(t *testing.T) {
	rendered, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "mcp", "clients", "orchestrator", "profiles", "collector.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(rendered), "\npath_scope:") != 1 {
		t.Fatal("the example profile no longer has one path_scope line")
	}
	old := strings.Replace(string(rendered), "\npath_scope:", "\nlegacy_scope:", 1)
	dir := t.TempDir()
	writeProfileFile(t, dir, "collector.yaml", old)
	if _, err := MigrateDir(dir, migrateOpts(legacyAliases)); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "collector.yaml"))
	if string(got) != string(rendered) {
		t.Errorf("the migrated profile differs from the render beyond the renamed line:\n%s", got)
	}
	// a key written otherwise is refused, never rewritten by re-encoding
	for _, body := range []string{"{agent_key: q, legacy_scope: {}}\n", "agent_key: q\n\"legacy_scope\": {}\n"} {
		d := t.TempDir()
		writeProfileFile(t, d, "q.yaml", body)
		if _, err := MigrateDir(d, migrateOpts(legacyAliases)); err == nil {
			t.Errorf("%q migrated", body)
		}
	}
}

func TestKeyAliases_AnEmptyFileSaysSo(t *testing.T) {
	for _, data := range []string{"", "# only a comment\n"} {
		if _, err := ParseKeyAliases([]byte(data)); err == nil || !strings.Contains(err.Error(), "the file is empty") {
			t.Errorf("%q: %v", data, err)
		}
	}
}

// An alias whose old name is also an extension key is refused before anything is written: the
// file would have read as the extension, and its migration as the scope.
func TestMigrateDir_RefusesAnAliasThatIsAnExtension(t *testing.T) {
	dir := t.TempDir()
	body := "agent_key: q\nqx: {writable_prefixes: [notes/q/]}\n"
	writeProfileFile(t, dir, "q.yaml", body)
	opts := withExt(Extension{Name: "qx", Opaque: true})
	opts.KeyAliases = KeyAliases{"qx": "path_scope"}
	if _, err := MigrateDir(dir, opts); err == nil {
		t.Fatal("an alias that is an extension key migrated")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "q.yaml")); string(b) != body {
		t.Errorf("the file was written:\n%s", b)
	}
}
