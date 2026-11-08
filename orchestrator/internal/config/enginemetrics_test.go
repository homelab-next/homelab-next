// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// The tests' engine names its metrics engine:*; nothing in this package names any engine's.
var testEngineMetrics = EngineMetrics{
	Load: []string{"engine:requests_running", "engine:requests_waiting"},
	KV:   KVMetrics{Info: "engine:cache_info", PoolLabel: "pool_tokens", Usage: "engine:cache_usage"},
}

func TestParse_ReadsAndChecksTheEngineMetrics(t *testing.T) {
	cfg := mustParse(t, scopeYAML+`
db_path: /var/lib/orchestrator/controller.db
profiles_dir: /etc/orchestrator/profiles
lessons_disabled: true
engine_metrics:
  load: [engine:requests_running, engine:requests_waiting]
  kv: {info: engine:cache_info, pool_label: pool_tokens, blocks_label: num_blocks, block_size_label: block_size, usage: engine:cache_usage}
`)
	m := cfg.EngineMetrics
	if len(m.Load) != 2 || m.KV.Info != "engine:cache_info" || m.KV.PoolLabel != "pool_tokens" || m.KV.BlockSizeLabel != "block_size" || m.KV.Usage != "engine:cache_usage" {
		t.Fatalf("engine metrics = %+v", m)
	}
	for _, bad := range []string{
		"engine_metrics: {load: [\"not a name\"]}\n",
		"engine_metrics: {kv: {pool_label: \"pool:tokens\"}}\n",
		"engine_metrics: {kv: {info: \"9starts-with-a-digit\"}}\n",
		"engine_metrics: {kv: {nope: x}}\n",
	} {
		if _, err := Parse([]byte(scopeYAML + "db_path: /var/lib/orchestrator/controller.db\nprofiles_dir: /p\nlessons_disabled: true\n" + bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestLoadEngineMetrics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "engine_metrics.yaml")
	writeFile(t, path, "load: [engine:requests_running]\nkv: {info: engine:cache_info, pool_label: pool_tokens}\n")
	m, err := LoadEngineMetrics(path)
	if err != nil || len(m.Load) != 1 || m.KV.PoolLabel != "pool_tokens" {
		t.Fatalf("m = %+v, %v", m, err)
	}
	for name, body := range map[string]string{
		"empty":         "",
		"names none":    "load: []\n",
		"unknown key":   "load: [engine:x]\nextra: 1\n",
		"a bad name":    "load: [\"engine x\"]\n",
		"not a mapping": "- engine:x\n",
	} {
		writeFile(t, path, body)
		if _, err := LoadEngineMetrics(path); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, err := LoadEngineMetrics(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("a missing file loaded")
	}
}

// The migration writes the site's engine metrics into a configuration whose backends have load
// probes; without them it says the controller will refuse the probes; a configuration that names
// them already is not given another set.
func TestMigrate_WritesTheSitesEngineMetrics(t *testing.T) {
	old := strings.Replace(oldConfig, "    base_url: http://engine-a.example.internal:8000/v1\n",
		"    base_url: http://engine-a.example.internal:8000/v1\n    load_probe_urls: [http://engine-a.example.internal:8000/metrics]\n", 1)
	if old == oldConfig {
		t.Fatal("the fixture did not change")
	}
	_, notes, err := Migrate([]byte(old))
	if err != nil || !strings.Contains(strings.Join(notes, "\n"), "names no engine_metrics") {
		t.Fatalf("without the site's names: notes %q, %v", notes, err)
	}
	m := testEngineMetrics
	out, notes, err := MigrateWith([]byte(old), MigrateOptions{EngineMetrics: &m})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(out)
	if err != nil || len(cfg.EngineMetrics.Load) != 2 || cfg.EngineMetrics.KV.PoolLabel != "pool_tokens" || notes[len(notes)-1] != "added the engine_metrics block" {
		t.Fatalf("migrated = %+v, %q, %v", cfg.EngineMetrics, notes, err)
	}
	if _, _, err := MigrateWith(out, MigrateOptions{EngineMetrics: &m}); err == nil {
		t.Error("a configuration naming its engine metrics was given another set")
	}
	if _, _, err := MigrateWith([]byte(old), MigrateOptions{EngineMetrics: &EngineMetrics{}}); err == nil {
		t.Error("an empty set was written")
	}
	if _, notes, _ := Migrate([]byte(oldConfig)); strings.Contains(strings.Join(notes, "\n"), "engine_metrics") {
		t.Errorf("a configuration without load probes got the note: %q", notes)
	}
}
