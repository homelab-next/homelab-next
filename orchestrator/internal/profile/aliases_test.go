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
		"not a plain name":      {"Legacy-Scope": "path_scope"},
		"dotted":                {"legacy.scope": "path_scope"},
		"a chain":               {"legacy_a": "legacy_b", "legacy_b": "path_scope"},
		"two names for one key": {"legacy_a": "path_scope", "legacy_b": "path_scope"},
	}
}

func TestMigrate_RewritesAProfilesDirectory(t *testing.T) {
	dir := t.TempDir()
	writeProfileFile(t, dir, "a.yaml", "# watcher\nagent_key: watcher\nlegacy_scope: # the scope\n  writable_prefixes: [notes/findings/watch/]\n")
	writeProfileFile(t, dir, "b.yaml", "agent_key: other\n")
	before, _ := os.ReadFile(filepath.Join(dir, "b.yaml"))
	notes, err := Migrate(dir, legacyAliases)
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
	if again, err := Migrate(dir, legacyAliases); err != nil || len(again) != 0 {
		t.Errorf("a second migration: %v, %v", again, err)
	}
	// one file setting both stops the migration before any file is written
	writeProfileFile(t, dir, "c.yaml", "agent_key: c\nlegacy_scope: {}\n")
	writeProfileFile(t, dir, "d.yaml", "agent_key: d\nlegacy_scope: {}\npath_scope: {}\n")
	if _, err := Migrate(dir, legacyAliases); err == nil {
		t.Fatal("a profile with both names migrated")
	}
	if c, _ := os.ReadFile(filepath.Join(dir, "c.yaml")); !strings.Contains(string(c), "legacy_scope") {
		t.Error("a file was written before the refusal")
	}
	if _, err := Migrate(dir, KeyAliases{"legacy_key": "agent_key"}); err == nil {
		t.Error("an invalid table migrated")
	}
}
