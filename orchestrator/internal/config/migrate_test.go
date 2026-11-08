// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/homelab-next/homelab-next/orchestrator/internal/pathscope"
)

// oldConfig is a fictional configuration in the private controller's keys: every key a
// migration renames or removes.
const oldConfig = scopeYAML + `# the controller's database
db_path: /var/lib/orchestrator/controller.db
hermes_local_home: /etc/orchestrator/runner/local # the primary engine
hermes_local_fallback_home: /etc/orchestrator/runner/fallback
hermes_cloud_home: /etc/orchestrator/runner/cloud
hermes_agent_timeout_seconds: 3600
hermes_agent_job_timeout_seconds: 7200
hermes_agent_stall_timeout_seconds: 600
hermes_agent_stall_poll_interval_seconds: 20
hermes_agent_liveness: progress
hermes_agent_max_turns: 80
hermes_agent_run_dir_base: /var/lib/orchestrator/runs
hermes_agent_env_allowlist: [LANG]
hermes_agent_job_home_root: /var/lib/orchestrator/homes
hermes_agent_interlock_wait_timeout_seconds: 600
hermes_agent_grants_catalog: /etc/orchestrator/mcp_catalog.yaml
backend_status_script: /usr/local/libexec/backend_status.py
passthrough_enabled: false
reject_unknown_agent_keys: true
backends:
  local:
    name: engine-a
    base_url: http://engine-a.example.internal:8000/v1
    api_key_env: ENGINE_A_KEY
  local_fallback:
    name: engine-b
    base_url: https://198.51.100.7
  cloud:
    name: cloud
    base_url: https://cloud.example.internal
    api_key_env: CLOUD_KEY
    openai_compatible: false
  additional:
  - name: engine-c
    base_url: http://engine-c.example.internal:8001
    hermes_home: /etc/orchestrator/runner/c
`

func TestMigrate_RewritesEveryOldKey(t *testing.T) {
	out, notes, err := Migrate([]byte(oldConfig))
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, gone := range []string{"hermes", "passthrough", "reject_unknown", "api_key_env", "openai_compatible", "base_url", "backend_status_script"} {
		if strings.Contains(text, gone) {
			t.Errorf("the migrated configuration still holds %q:\n%s", gone, text)
		}
	}
	for _, kept := range []string{"# the controller's database", "# the primary engine"} {
		if !strings.Contains(text, kept) {
			t.Errorf("comment %q lost:\n%s", kept, text)
		}
	}
	cfg, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	b := cfg.Backends
	if b.Local.Home != "/etc/orchestrator/runner/local" || b.LocalFallback.Home != "/etc/orchestrator/runner/fallback" || b.Cloud.Home != "/etc/orchestrator/runner/cloud" ||
		b.Additional[0].Home != "/etc/orchestrator/runner/c" {
		t.Errorf("homes = %+v", b)
	}
	if b.Local.Endpoint != "engine-a.example.internal:8000" || b.LocalFallback.Endpoint != "198.51.100.7:443" || b.Cloud.Endpoint != "cloud.example.internal:443" ||
		b.Additional[0].Endpoint != "engine-c.example.internal:8001" {
		t.Errorf("endpoints = %+v", b)
	}
	r := cfg.Runner
	if r.TimeoutSeconds != 3600 || r.JobTimeoutSeconds != 7200 || r.StallTimeoutSeconds != 600 || r.StallPollIntervalSeconds != 20 || r.Liveness != "progress" ||
		r.MaxTurns != 80 || r.RunDirBase == "" || len(r.EnvAllowlist) != 1 || r.JobHomeRoot == "" {
		t.Errorf("runner = %+v", r)
	}
	if cfg.InterlockWaitTimeoutSeconds != 600 || cfg.GrantsCatalog == "" || !slices.Equal(cfg.BackendStatusCommand, []string{"python3", "/usr/local/libexec/backend_status.py", "--json"}) {
		t.Errorf("config = %+v", cfg)
	}
	if len(cfg.Notices) != 0 {
		t.Errorf("a migrated configuration loads without notices: %v", cfg.Notices)
	}
	// one note per change, deterministic
	if len(notes) != 26 {
		t.Errorf("%d notes: %v", len(notes), notes)
	}
	_, again, _ := Migrate([]byte(oldConfig))
	if !slices.Equal(notes, again) {
		t.Errorf("notes differ between runs:\n%v\n%v", notes, again)
	}
	// idempotent: a migrated configuration needs nothing
	out2, notes2, err := Migrate(out)
	if err != nil || len(notes2) != 0 || string(out2) != string(out) {
		t.Errorf("a second migration changed something: %v %v", notes2, err)
	}
}

// Loading reads an old key under its new name and says so; a dropped key is refused.
func TestParse_ReadsOldKeysAndRefusesDroppedOnes(t *testing.T) {
	cfg := mustParse(t, scopeYAML+"hermes_local_home: /etc/orchestrator/runner/local\nhermes_agent_max_turns: 5\nbackends: {local: {base_url: \"http://192.0.2.10:8000/v1\"}}\n")
	if cfg.Backends.Local.Home != "/etc/orchestrator/runner/local" || cfg.Runner.MaxTurns != 5 || cfg.Backends.Local.Endpoint != "192.0.2.10:8000" {
		t.Errorf("config = %+v", cfg)
	}
	if len(cfg.Notices) != 3 || !strings.Contains(strings.Join(cfg.Notices, "\n"), "read hermes_local_home as backends.local.home") { // scrub-allow: config key paths, not host names
		t.Errorf("notices = %v", cfg.Notices)
	}
	for _, body := range []string{
		"passthrough_enabled: false\n", "passthrough_enabled: true\n", "reject_unknown_agent_keys: true\n",
		"backends: {local: {api_key_env: K}}\n", "backends: {cloud: {openai_compatible: true}}\n",
		"backends: {additional: [{api_key_env: K}]}\n",
	} {
		if _, err := Parse([]byte(scopeYAML + body)); err == nil || !strings.Contains(err.Error(), "migration") {
			t.Errorf("%q: %v", body, err)
		}
	}
}

// A configuration that sets an old key and its new key is refused, whichever way (two old
// spellings of one setting included), and so is a value the conversion cannot read.
func TestParse_RefusesAnOldAndANewKey(t *testing.T) {
	for name, body := range map[string]string{
		"top-level old and new":  "hermes_agent_max_turns: 5\nrunner: {max_turns: 6}\n",
		"same value both ways":   "hermes_agent_liveness: cpu\nrunner: {liveness: cpu}\n",
		"backend old and new":    "backends: {local: {hermes_home: /a, home: /b}}\n",
		"two old spellings":      "hermes_local_home: /a\nbackends: {local: {hermes_home: /b}}\n",
		"top-level into backend": "hermes_cloud_home: /a\nbackends: {cloud: {home: /b}}\n",
		"base_url and endpoint":  "backends: {local: {base_url: \"http://192.0.2.10:8000\", endpoint: \"192.0.2.10:8000\"}}\n",
		"script and command":     "backend_status_script: /x.py\nbackend_status_command: [/x]\n",
		"base_url not a URL":     "backends: {local: {base_url: \"engine-a:8000\"}}\n",
		"base_url other scheme":  "backends: {local: {base_url: \"ftp://engine-a:8000\"}}\n",
	} {
		_, err := Parse([]byte(scopeYAML + body))
		if err == nil {
			t.Errorf("%s: loaded", name)
		}
		if _, _, merr := Migrate([]byte(scopeYAML + body)); merr == nil {
			t.Errorf("%s: migrated", name)
		}
	}
}

func TestMigrate_LeavesANeutralConfigurationAlone(t *testing.T) {
	body := scopeYAML + "# kept as written\nrunner: {max_turns: 3}\n"
	out, notes, err := Migrate([]byte(body))
	if err != nil || len(notes) != 0 || string(out) != body {
		t.Fatalf("Migrate = %q, %v, %v", out, notes, err)
	}
	if _, _, err := Migrate([]byte("db_path: /a\ndb_path: /b\n")); err == nil {
		t.Error("a repeated key migrated")
	}
	// the result must load: a migration does not write a configuration this controller refuses
	if _, _, err := Migrate([]byte("hermes_agent_max_turns: 3\napi_auth: {enabled: false}\n")); err == nil || !strings.Contains(err.Error(), "does not load") {
		t.Errorf("a configuration without a scope block migrated: %v", err)
	}
}

// docs/orchestration-controller.md prints the table of old and new keys; it is the table
// Renames and Dropped hold.
func TestTheDocsPrintTheMigrationTable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "orchestration-controller.md"))
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile("(?m)^\\| `([a-z_.*\\[\\]]+)` \\| (?:`([a-z_.*]+)`|not ported)")
	var renames, dropped []string
	for _, m := range row.FindAllStringSubmatch(string(raw), -1) {
		if m[2] == "" {
			dropped = append(dropped, m[1])
		} else {
			renames = append(renames, m[1]+" -> "+m[2])
		}
	}
	var wantRenames, wantDropped []string
	for _, r := range Renames {
		wantRenames = append(wantRenames, r.Old+" -> "+r.New)
	}
	wantDropped = droppedKeys()
	slices.Sort(dropped)
	if !slices.Equal(renames, wantRenames) || !slices.Equal(dropped, wantDropped) {
		t.Errorf("docs table:\n renames %v\n dropped %v\nwant\n renames %v\n dropped %v", renames, dropped, wantRenames, wantDropped)
	}
}

// The private controller hard-coded its tree's zones, so its configuration has no scope block:
// the migration writes the one it is given, every key present, so the lab's file migrates in one
// command; one that already has a block is refused.
func TestMigrate_AddsTheScopeBlock(t *testing.T) {
	old := strings.Replace(oldConfig, zonesYAML, "", 1)
	if _, _, err := Migrate([]byte(old)); err == nil {
		t.Fatal("a configuration without a scope block migrated without one")
	}
	z := pathscope.Zones{DeniedRoots: []string{"owner"}, FindingsRoot: "notes/findings/", ReservedNames: []string{"operator"}}
	out, notes, err := MigrateWith([]byte(old), MigrateOptions{Scope: &z})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(out)
	if err != nil || cfg.Zones().FindingsRoot != "notes/findings/" || !cfg.Zones().ReservedName("operator") || notes[len(notes)-1] != "added the scope block" {
		t.Fatalf("migrated = %v, %v, %v", cfg.Zones(), notes, err)
	}
	if !strings.Contains(string(out), "shared_write: []") {
		t.Errorf("an empty key was left out:\n%s", out)
	}
	if _, _, err := MigrateWith([]byte(oldConfig), MigrateOptions{Scope: &z}); err == nil {
		t.Error("a configuration with a scope block was given another")
	}
}

// An empty base_url (a backend left unset) becomes no endpoint, with a note; an unreadable one is
// refused without quoting it, since a URL may carry a password.
func TestMigrate_BaseURLEdges(t *testing.T) {
	out, notes, err := Migrate([]byte(scopeYAML + "backends: {local: {name: a, base_url: \"\"}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "endpoint") || len(notes) != 2 || !strings.Contains(notes[0], "empty") {
		t.Errorf("out = %s notes = %v", out, notes)
	}
	_, _, err = Migrate([]byte(scopeYAML + "backends: {local: {base_url: \"engine-user:s3cretpw@\"}}\n"))
	if err == nil || strings.Contains(err.Error(), "s3cretpw") {
		t.Errorf("err = %v", err)
	}
}

// A migration moves keys by name, so a configuration that reaches one through an anchor or a
// merge key is refused; and an unchanged configuration is still held to loading.
func TestMigrate_RefusesAliasesAndChecksAnUnchangedFile(t *testing.T) {
	for _, body := range []string{
		"base: &r {max_turns: 3}\nrunner: *r\n",
		"base: &r {max_turns: 3}\nrunner: {<<: *r}\n",
	} {
		if _, _, err := Migrate([]byte(scopeYAML + body)); err == nil {
			t.Errorf("%q migrated", body)
		}
		if _, err := Parse([]byte(scopeYAML + body)); err == nil {
			t.Errorf("%q parsed", body)
		}
	}
	if _, _, err := Migrate([]byte(scopeYAML + "runner: {liveness: sometimes}\n")); err == nil {
		t.Error("an unchanged configuration that does not load migrated")
	}
}

// A comment stays with its key: a line comment on an old key ends up on the line of its new key.
func TestMigrate_KeepsCommentsWithTheirKeys(t *testing.T) {
	out, _, err := Migrate([]byte(oldConfig))
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "# the primary engine") {
			line = l
		}
	}
	if !strings.Contains(line, "home: /etc/orchestrator/runner/local") {
		t.Errorf("the comment sits on %q:\n%s", line, out)
	}
	if !strings.Contains(string(out), "# the controller's database\ndb_path:") {
		t.Errorf("a head comment moved:\n%s", out)
	}
}

// The private controller built its local backend with the interlock off whatever its file said;
// here unset means on, so a migration from its keys states the old behaviour, and a configuration
// already in the new keys is left alone.
func TestMigrate_KeepsTheLocalBackendsInterlockOff(t *testing.T) {
	out, notes, err := Migrate([]byte(oldConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(out)
	if err != nil || cfg.Backends.Local.InterlockRequired() || !cfg.Backends.LocalFallback.InterlockRequired() {
		t.Fatalf("interlock: local %v, fallback %v (%v)", cfg.Backends.Local.InterlockRequired(), cfg.Backends.LocalFallback.InterlockRequired(), err)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "needs_interlock: false") {
		t.Errorf("notes = %v", notes)
	}
	set := strings.Replace(oldConfig, "    name: engine-a\n", "    name: engine-a\n    needs_interlock: true\n", 1)
	out, _, err = Migrate([]byte(set))
	if cfg, _ := Parse(out); err != nil || !cfg.Backends.Local.InterlockRequired() {
		t.Errorf("an explicit needs_interlock was overwritten (%v)", err)
	}
	neutral := scopeYAML + "backends: {local: {name: engine-a}}\n"
	if out, notes, err := Migrate([]byte(neutral)); err != nil || len(notes) != 0 || string(out) != neutral {
		t.Errorf("a configuration in the new keys was changed: %v %v", notes, err)
	}
}

// The interlock is written only for a configuration in the private controller's keys: a dropped
// key or a site rename alone does not make one.
func TestMigrate_InterlockOnlyForThePrivateControllersKeys(t *testing.T) {
	for name, body := range map[string]string{
		"dropped key only": scopeYAML + "passthrough_enabled: false\nbackends: {local: {name: engine-a}}\n",
		"site rename only": scopeYAML + "legacy_root: /srv/notes\nbackends: {local: {name: engine-a}}\n",
	} {
		out, _, err := MigrateWith([]byte(body), MigrateOptions{ExtraRenames: legacyRenames})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(string(out), "needs_interlock") {
			t.Errorf("%s: the interlock was written:\n%s", name, out)
		}
	}
}

// The private controller's configuration sets no prompt_contracts (its contracts were built in);
// migrated, it still sets none and so gets the built-in ones.
func TestMigrate_UnsetContractsStayTheDefaults(t *testing.T) {
	out, _, err := Migrate([]byte(oldConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PromptContracts != nil || cfg.PromptContractsAppend != nil {
		t.Fatalf("the migration set contracts: %q, %q", cfg.PromptContracts, cfg.PromptContractsAppend)
	}
	defaults := []string{"[built-in] one", "[built-in] two", "[built-in] three"}
	if got, err := cfg.PromptContractTexts(t.TempDir(), defaults); err != nil || !slices.Equal(got, defaults) {
		t.Fatalf("contracts = %q, %v; want the defaults", got, err)
	}
}

// A configuration in the private controller's keys served without a token unless it said
// otherwise; here authentication is on unless the file says false. The migration never decides to
// serve without a token: a file with no tokens file is refused, naming both remedies, unless the
// operator asks (AllowUnauthenticatedAPI), and then it says enabled: false; a file that names a
// tokens file is on, with a note.
func TestMigrate_NeverTurnsAuthenticationOffByItself(t *testing.T) {
	for name, old := range map[string]string{
		"no block":         zonesYAML + "hermes_local_home: /a\n",
		"a null block":     zonesYAML + "hermes_local_home: /a\napi_auth: null\n",
		"no tokens file":   zonesYAML + "hermes_local_home: /a\napi_auth: {}\n",
		"blank token file": zonesYAML + "hermes_local_home: /a\napi_auth: {tokens_file: \"\"}\n",
	} {
		_, _, err := Migrate([]byte(old))
		if err == nil || !strings.Contains(err.Error(), "tokens_file") || !strings.Contains(err.Error(), "AllowUnauthenticatedAPI") {
			t.Errorf("%s: Migrate = %v, want a refusal naming both remedies", name, err)
			continue
		}
		var opts MigrateOptions
		opts.AllowUnauthenticatedAPI = true
		out, notes, err := MigrateWith([]byte(old), opts)
		if err != nil {
			t.Errorf("%s: with the option: %v", name, err)
			continue
		}
		if cfg := mustParse(t, string(out)); cfg.APIAuth.On() || !strings.Contains(strings.Join(notes, "\n"), "AllowUnauthenticatedAPI") {
			t.Errorf("%s: migrated = %s, notes %v", name, out, notes)
		}
	}
	out, notes, err := Migrate([]byte(zonesYAML + "hermes_local_home: /a\napi_auth: {tokens_file: /etc/orchestrator/t.yaml}\n"))
	if err != nil || !mustParse(t, string(out)).APIAuth.On() || !strings.Contains(strings.Join(notes, "\n"), "now on") {
		t.Fatalf("a tokens file = %s, %v, %v: want on, with a note", out, notes, err)
	}
}

// A null api_auth is refused on load, and a configuration with authentication off says so on
// every load.
func TestParse_NullAuthAndTheOffNotice(t *testing.T) {
	if _, err := Parse([]byte(zonesYAML + "api_auth: null\n")); err == nil || !strings.Contains(err.Error(), "null") {
		t.Fatalf("api_auth: null = %v", err)
	}
	cfg := mustParse(t, zonesYAML+"api_auth: {enabled: false}\n")
	if !strings.Contains(strings.Join(cfg.Notices, "\n"), "without a token") {
		t.Fatalf("notices = %v", cfg.Notices)
	}
	if cfg := mustParse(t, scopeYAML); len(cfg.Notices) != 0 {
		t.Fatalf("auth on noted: %v", cfg.Notices)
	}
}
