// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// legacyRenames is a fictional site's table: its old key names are the site's, never spelt here.
var legacyRenames = SiteRenames{"legacy_root": "tree_root", "legacy_catalog_path": "grants_catalog"}

func TestSiteRenames_LoadMigrateAndRefuseBoth(t *testing.T) {
	body := scopeYAML + "legacy_root: /srv/notes # the tree\nlegacy_catalog_path: /etc/orchestrator/mcp_catalog.yaml\n"
	if _, err := Parse([]byte(body)); err == nil {
		t.Fatal("a site's old key loaded without its renames")
	}
	cfg, err := ParseWith([]byte(body), ParseOptions{ExtraRenames: legacyRenames})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TreeRoot != "/srv/notes" || cfg.GrantsCatalog == "" || len(cfg.Notices) != 2 || !strings.Contains(cfg.Notices[1], "read legacy_root as tree_root (a site rename)") {
		t.Errorf("config = %q %q, notices %v", cfg.TreeRoot, cfg.GrantsCatalog, cfg.Notices)
	}
	out, notes, err := MigrateWith([]byte(body), MigrateOptions{ExtraRenames: legacyRenames})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "legacy_") || !strings.Contains(string(out), "tree_root: /srv/notes # the tree") || len(notes) != 2 {
		t.Errorf("migrated:\n%s\nnotes %v", out, notes)
	}
	both := scopeYAML + "legacy_root: /a\ntree_root: /b\n"
	if _, err := ParseWith([]byte(both), ParseOptions{ExtraRenames: legacyRenames}); err == nil {
		t.Error("an old and a new name of one key loaded")
	}
	if _, _, err := MigrateWith([]byte(both), MigrateOptions{ExtraRenames: legacyRenames}); err == nil {
		t.Error("an old and a new name of one key migrated")
	}
}

// The table can only give an existing key a second name.
func TestSiteRenames_Validate(t *testing.T) {
	for name, r := range map[string]SiteRenames{
		"target not a key":         {"legacy_root": "tree_roots"},
		"old name is a key":        {"db_path": "tree_root"},
		"old name is built in":     {"hermes_agent_max_turns": "tree_root"},
		"old name dropped":         {"passthrough_enabled": "tree_root"},
		"old name dotted":          {"legacy.root": "tree_root"},
		"not a key path":           {"Legacy-Root": "tree_root"},
		"into the scope zones":     {"legacy_denied": "scope.denied_roots"},
		"the scope block itself":   {"legacy_scope": "scope"},
		"into the API credentials": {"legacy_tokens": "api_auth.tokens_file"},
		"a chain":                  {"legacy_a": "legacy_b", "legacy_b": "tree_root"},
		"a cycle":                  {"legacy_a": "legacy_b", "legacy_b": "legacy_a"},
		"two names for one key":    {"legacy_a": "tree_root", "legacy_b": "tree_root"},
		"a key of a list entry":    {"legacy_home": "backends.additional.home"}, // scrub-allow: a config key path, not a host name
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: validated", name)
		}
		if _, err := ParseWith([]byte(scopeYAML), ParseOptions{ExtraRenames: r}); err == nil {
			t.Errorf("%s: a load accepted the table", name)
		}
	}
	if err := (SiteRenames{"legacy_home": "backends.local.home"}).Validate(); err != nil { // scrub-allow: config key paths, not host names
		t.Errorf("a dotted target: %v", err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "renames.yaml")
	if err := os.WriteFile(p, []byte("legacy_root: tree_root\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r, err := LoadSiteRenames(p); err != nil || r["legacy_root"] != "tree_root" {
		t.Fatalf("LoadSiteRenames = %v, %v", r, err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSiteRenames(link); err == nil {
		t.Error("a renames file behind a symbolic link loaded")
	}
	for _, bad := range []string{"legacy_root: tree_root\nlegacy_root: grants_catalog\n", "- a\n", "legacy_root: tree_roots\n"} {
		if _, err := ParseSiteRenames([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestSiteRenames_AnEmptyFileSaysSo(t *testing.T) {
	for _, data := range []string{"", "\n", "# only a comment\n"} {
		if _, err := ParseSiteRenames([]byte(data)); err == nil || !strings.Contains(err.Error(), "the file is empty") {
			t.Errorf("%q: %v", data, err)
		}
	}
}
