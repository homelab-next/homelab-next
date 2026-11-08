// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/homelab-next/homelab-next/orchestrator/internal/profile"
)

// scopeYAML is a fictional tree's zones, every key set.
const scopeYAML = `scope:
  denied_roots: [owner]
  findings_root: notes/findings/
  shared_write: [inbox/]
  reserved_names: [operator]
`

func mustParse(t *testing.T, body string) Config {
	t.Helper()
	cfg, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoad_ParsesTheNeutralKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.yaml")
	writeFile(t, path, scopeYAML+`
db_path: /var/lib/orchestrator/controller.db
http_addr: 127.0.0.1:8088
lock_path: /run/orchestrator/interlock.lock
backends:
  local:
    name: engine-a
    home: /etc/orchestrator/runner/local
    endpoint: engine-a.example.internal:8000
    weight: 2
    tags: [general]
    max_context: 131072
    max_concurrent: 4
    load_probe_urls: [http://engine-a.example.internal:8000/metrics]
    health_url: http://engine-a.example.internal:8000/health
    needs_interlock: false
  cloud: {name: cloud, home: /etc/orchestrator/runner/cloud}
  additional:
  - {name: engine-b, home: /etc/orchestrator/runner/b, endpoint: "198.51.100.7:8000"}
runner:
  timeout_seconds: 3600
  job_timeout_seconds: 7200
  stall_timeout_seconds: 600
  stall_poll_interval_seconds: 20
  liveness: progress
  max_turns: 80
  run_dir_base: /var/lib/orchestrator/runs
  env_allowlist: [LANG, LC_*]
  job_home_root: /var/lib/orchestrator/homes
interlock_wait_timeout_seconds: 600
grants_catalog: /etc/orchestrator/mcp_catalog.yaml
profiles_dir: /etc/orchestrator/profiles
backend_status_command: [/usr/local/bin/backend-status, --json]
lessons_path: /srv/notes/lessons
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DBPath != "/var/lib/orchestrator/controller.db" || cfg.HTTPAddr != "127.0.0.1:8088" || cfg.LockPath == "" {
		t.Errorf("top level = %+v", cfg)
	}
	l := cfg.Backends.Local
	if l.Name != "engine-a" || l.Home == "" || l.Endpoint != "engine-a.example.internal:8000" || l.Weight != 2 || l.MaxContext != 131072 ||
		l.MaxConcurrent != 4 || len(l.LoadProbeURLs) != 1 || l.HealthURL == "" || l.InterlockRequired() {
		t.Errorf("local = %+v", l)
	}
	if !cfg.Backends.Cloud.InterlockRequired() || len(cfg.Backends.Additional) != 1 || cfg.Backends.Additional[0].Endpoint != "198.51.100.7:8000" {
		t.Errorf("backends = %+v", cfg.Backends)
	}
	want := Runner{TimeoutSeconds: 3600, JobTimeoutSeconds: 7200, StallTimeoutSeconds: 600, StallPollIntervalSeconds: 20, Liveness: "progress",
		MaxTurns: 80, RunDirBase: "/var/lib/orchestrator/runs", EnvAllowlist: []string{"LANG", "LC_*"}, JobHomeRoot: "/var/lib/orchestrator/homes"}
	if !reflect.DeepEqual(cfg.Runner, want) {
		t.Errorf("runner = %+v", cfg.Runner)
	}
	if cfg.InterlockWaitTimeoutSeconds != 600 || cfg.GrantsCatalog == "" || len(cfg.BackendStatusCommand) != 2 || len(cfg.Notices) != 0 {
		t.Errorf("config = %+v", cfg)
	}
	if !cfg.Zones().Validated() || cfg.Zones().FindingsRoot != "notes/findings/" || !cfg.Zones().ReservedName("operator") {
		t.Errorf("zones = %+v", cfg.Zones())
	}
}

func TestLoad_MissingFileIsAnError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("a missing config file loaded")
	}
}

// Decoding is strict, and a repeated key is refused (a reader would see one value, a migration
// the other).
func TestParse_IsStrict(t *testing.T) {
	for name, body := range map[string]string{
		"unknown top-level key":  "db_pth: /x\n",
		"unknown nested key":     "runner: {timeout: 5}\n",
		"unknown backend key":    "backends: {local: {nam: a}}\n",
		"unknown scope key":      "scope: {denied_roots: [owner], findings_root: '', shared_write: [], reserved_names: [], extra: 1}\n",
		"repeated top-level key": "db_path: /a\ndb_path: /b\n",
		"repeated nested key":    "runner: {liveness: cpu, liveness: progress}\n",
		"not a mapping":          "- a\n",
	} {
		if _, err := Parse([]byte(scopeYAML + body)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// The scope block's keys are required by presence: an absent key would read as its empty value,
// and an empty value there is a decision. An explicit empty denied_roots also needs
// allow_no_denied_roots.
func TestParse_ScopeIsRequiredKeyByKey(t *testing.T) {
	if _, err := Parse([]byte("db_path: /x\n")); err == nil || !strings.Contains(err.Error(), "scope") {
		t.Fatalf("no scope block: %v", err)
	}
	full := map[string]string{"denied_roots": "[owner]", "findings_root": "notes/findings/", "shared_write": "[inbox/]", "reserved_names": "[]"}
	for _, leave := range scopeKeys {
		var b strings.Builder
		b.WriteString("scope:\n")
		for _, k := range scopeKeys {
			if k != leave {
				b.WriteString("  " + k + ": " + full[k] + "\n")
			}
		}
		if _, err := Parse([]byte(b.String())); err == nil || !strings.Contains(err.Error(), leave) {
			t.Errorf("scope without %s: %v", leave, err)
		}
	}
	none := "scope:\n  denied_roots: []\n  findings_root: ''\n  shared_write: []\n  reserved_names: []\n"
	if _, err := Parse([]byte(none)); err == nil {
		t.Error("an empty denied_roots loaded without allow_no_denied_roots")
	}
	cfg := mustParse(t, none+"  allow_no_denied_roots: true\n")
	if !cfg.Zones().Validated() || len(cfg.Zones().DeniedRoots) != 0 {
		t.Errorf("zones = %+v", cfg.Zones())
	}
	if _, err := Parse([]byte("scope:\n  denied_roots: [a/b]\n  findings_root: ''\n  shared_write: []\n  reserved_names: []\n")); err == nil {
		t.Error("a zones value pathscope refuses loaded")
	}
}

func TestParse_Checks(t *testing.T) {
	for name, body := range map[string]string{
		"liveness":          "runner: {liveness: sometimes}\n",
		"negative timeout":  "runner: {timeout_seconds: -1}\n",
		"negative turns":    "runner: {max_turns: -3}\n",
		"kv fraction":       "kv_budget_fraction: 1.5\n",
		"endpoint is a URL": "backends: {local: {endpoint: \"http://engine-a.example.internal:8000\"}}\n",
		"endpoint no port":  "backends: {additional: [{endpoint: engine-a.example.internal}]}\n",
		"relative command":  "backend_status_command: [bin/status]\n",
		"tag prefix comma":  "events: {gateway_tag_prefix: \"a,b\"}\n",
		"relative lock":     "lock_path: run/backend.lock\n",
		"unclean lock":      "lock_path: /run/x/../backend.lock\n",
		"tag prefix space":  "events: {gateway_tag_prefix: \"job \"}\n",
	} {
		if _, err := Parse([]byte(scopeYAML + body)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// TestRegisters_FailClosed: no built-in register paths and no silent switch-off.
func TestRegisters_FailClosed(t *testing.T) {
	for name, tc := range map[string]struct {
		body             string
		lessons, runbook string
		wantErr          bool
	}{
		"unset":                   {body: "db_path: /tmp/x.db\n", wantErr: true},
		"runbooks only":           {body: "runbooks_path: /notes/runbooks\n", wantErr: true},
		"lessons":                 {body: "lessons_path: /notes/lessons\n", lessons: "/notes/lessons"},
		"both":                    {body: "lessons_path: /notes/lessons\nrunbooks_path: /notes/runbooks\n", lessons: "/notes/lessons", runbook: "/notes/runbooks"},
		"disabled":                {body: "lessons_disabled: true\n"},
		"disabled false":          {body: "lessons_disabled: false\n", wantErr: true},
		"disabled + lessons_path": {body: "lessons_disabled: true\nlessons_path: /notes/lessons\n", wantErr: true},
		"disabled + runbooks":     {body: "lessons_disabled: true\nrunbooks_path: /notes/runbooks\n", wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			l, r, err := mustParse(t, scopeYAML+tc.body).Registers()
			if (err != nil) != tc.wantErr || l != tc.lessons || r != tc.runbook {
				t.Fatalf("Registers() = %q, %q, %v", l, r, err)
			}
		})
	}
}

// Authentication is on unless the file turns it off.
func TestParse_APIAuthIsOnByDefault(t *testing.T) {
	if cfg := mustParse(t, scopeYAML+"api_auth: {tokens_file: /etc/orchestrator/api-tokens.yaml}\n"); !cfg.APIAuth.On() {
		t.Error("an api_auth block without enabled is off")
	}
	if cfg := mustParse(t, scopeYAML+"api_auth: {enabled: false}\n"); cfg.APIAuth.On() {
		t.Error("enabled: false is on")
	}
}

func TestParse_APIAuthEventsAndAdmissionDefaults(t *testing.T) {
	cfg := mustParse(t, scopeYAML)
	if !cfg.APIAuth.On() || cfg.TokenWeightedAdmission || cfg.KVBudgetFraction != 0 || cfg.PrimaryFirst || cfg.Events.ForwarderURL != "" {
		t.Errorf("defaults = %+v", cfg)
	}
	cfg = mustParse(t, scopeYAML+"api_auth: {enabled: true, tokens_file: /etc/orchestrator/api-tokens.yaml}\n"+
		"events: {forwarder_url: https://events.example.internal/ingest, token_env: EVENTS_TOKEN, queue_size: 10, gateway_tag_prefix: \"job:\"}\n"+
		"token_weighted_admission: true\nkv_budget_fraction: 0.7\nprimary_first: true\n")
	if !cfg.APIAuth.On() || cfg.APIAuth.TokensFile == "" || cfg.Events.QueueSize != 10 || cfg.Events.Source != "" || cfg.Events.GatewayTagPrefix != "job:" ||
		!cfg.TokenWeightedAdmission || cfg.KVBudgetFraction != 0.7 || !cfg.PrimaryFirst {
		t.Errorf("parsed = %+v", cfg)
	}
}

// The configuration names no inference URL: the controller calls no backend itself (a runner
// session does, through the gateway its home configures), so every URL key is a probe or the
// event forwarder; and no key names a product or the passthrough.
func TestTheConfigurationNamesNoInferenceURLAndNoProduct(t *testing.T) {
	probes := []string{"backends.local.health_url", "backends.local.load_probe_urls", "events.forwarder_url"} // scrub-allow: config key paths, not host names
	var urls []string
	for _, k := range allKeys(reflect.TypeFor[Config](), "") {
		if strings.Contains(k, "url") && strings.HasPrefix(k, "backends.") {
			k = "backends.local." + k[strings.LastIndexByte(k, '.')+1:] // scrub-allow: config key paths, not host names
		}
		if strings.Contains(k, "url") && !slices.Contains(urls, k) {
			urls = append(urls, k)
		}
		for _, bad := range []string{"hermes", "passthrough", "openai", "api_key", "base_url"} {
			if strings.Contains(k, bad) {
				t.Errorf("config key %s names %q", k, bad)
			}
		}
	}
	slices.Sort(urls)
	slices.Sort(probes)
	if !slices.Equal(urls, probes) {
		t.Errorf("URL keys = %v, want only the probes and the forwarder %v", urls, probes)
	}
}

// allKeys lists every YAML key path of a struct type.
func allKeys(t reflect.Type, at string) []string {
	var out []string
	for f := range t.Fields() {
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "" || name == "-" {
			continue
		}
		out = append(out, at+name)
		ft := f.Type
		for ft.Kind() == reflect.Slice || ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct && ft.PkgPath() == reflect.TypeFor[Config]().PkgPath() {
			out = append(out, allKeys(ft, at+name+".")...)
		}
	}
	return out
}

// TestPromptContractTexts: unset = the defaults; prompt_contracts replaces them and
// prompt_contracts_append adds after them, files read relative to the config's directory with one
// trailing newline dropped; a missing file is an error.
func TestPromptContractTexts(t *testing.T) {
	dir := t.TempDir()
	defaults := []string{"[built-in] one", "[built-in] two"}
	got, err := (Config{}).PromptContractTexts(dir, defaults)
	if err != nil || !slices.Equal(got, defaults) {
		t.Fatalf("unset = %q, %v; want the defaults", got, err)
	}
	got[0] = "changed"
	if defaults[0] != "[built-in] one" {
		t.Fatal("the result aliases the defaults")
	}
	writeFile(t, filepath.Join(dir, "a.md"), "[a] first\n")
	abs := filepath.Join(t.TempDir(), "b.md")
	writeFile(t, abs, "[b] second\n\n")
	if got, err = (Config{PromptContracts: []string{"a.md", abs}}).PromptContractTexts(dir, defaults); err != nil || !slices.Equal(got, []string{"[a] first", "[b] second\n"}) {
		t.Fatalf("replaced = %q, %v", got, err)
	}
	if got, err = (Config{PromptContractsAppend: []string{"a.md"}}).PromptContractTexts(dir, defaults); err != nil || !slices.Equal(got, []string{"[built-in] one", "[built-in] two", "[a] first"}) {
		t.Fatalf("appended = %q, %v", got, err)
	}
	if got, err = (Config{PromptContracts: []string{}, PromptContractsAppend: []string{"a.md"}}).PromptContractTexts(dir, defaults); err != nil || !slices.Equal(got, []string{"[a] first"}) {
		t.Fatalf("replaced by nothing, then appended = %q, %v", got, err)
	}
	for _, c := range []Config{{PromptContracts: []string{"missing.md"}}, {PromptContractsAppend: []string{"missing.md"}}} {
		if _, err := c.PromptContractTexts(dir, defaults); err == nil {
			t.Fatalf("%+v: a missing contract file must be an error", c)
		}
	}
}

// An explicit empty list is the opt-out: no contract, and the configuration loads.
func TestPromptContracts_EmptyListIsNone(t *testing.T) {
	cfg := mustParse(t, scopeYAML+"prompt_contracts: []\n")
	if got, err := cfg.PromptContractTexts(t.TempDir(), []string{"[d]"}); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("prompt_contracts: [] = %#v, %v; want empty, non-nil", got, err)
	}
	if got, err := mustParse(t, scopeYAML).PromptContractTexts(t.TempDir(), []string{"[d]"}); err != nil || !slices.Equal(got, []string{"[d]"}) {
		t.Fatalf("unset = %#v, %v; want the defaults", got, err)
	}
}

// TestProfileLoadOptions: the prompt-context lists become the profile loader's options (a
// relative prompt_dir is relative to the config's directory), the scope zones go with them, and
// extensions are data: a schema inline or in a file, or opaque, named so the caller logs it.
func TestProfileLoadOptions(t *testing.T) {
	dir := t.TempDir()
	cfg := mustParse(t, scopeYAML+`
prompt_dir: prompt
prompt_state_files: [/srv/notes/state.json]
facts_commands:
  example:
    argv: [/usr/local/bin/facts, --json]
    env: [EXAMPLE_ENDPOINT]
`)
	opts, opaque, err := cfg.ProfileLoadOptions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if opts.PromptDir != filepath.Join(dir, "prompt") || !reflect.DeepEqual(opts.StateFiles, []string{"/srv/notes/state.json"}) ||
		!reflect.DeepEqual(opts.FactsCommands["example"], profile.FactsCommand{Argv: []string{"/usr/local/bin/facts", "--json"}, Env: []string{"EXAMPLE_ENDPOINT"}}) ||
		len(opts.Extensions) != 0 || len(opaque) != 0 || !opts.Zones.Validated() {
		t.Fatalf("opts = %+v, opaque %v", opts, opaque)
	}
	writeFile(t, filepath.Join(dir, "scope.schema.json"), `{"type": "array", "items": {"type": "string"}}`)
	cfg = mustParse(t, scopeYAML+`
profile_extensions: [example_opaque, example_inline, example_file]
profile_extension_schemas:
  example_opaque: opaque
  example_inline: {type: object, additionalProperties: false, properties: {n: {type: integer}}}
  example_file: scope.schema.json
`)
	opts, opaque, err = cfg.ProfileLoadOptions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.Extensions) != 3 || !opts.Extensions[0].Opaque || opts.Extensions[1].Schema == nil || opts.Extensions[2].Schema == nil || !reflect.DeepEqual(opaque, []string{"example_opaque"}) {
		t.Fatalf("extensions = %+v, opaque %v", opts.Extensions, opaque)
	}
	for name, body := range map[string]string{
		"listed name with no entry":   "profile_extensions: [a]\n",
		"schema for an unlisted name": "profile_extensions: [a]\nprofile_extension_schemas: {a: opaque, b: {type: object}}\n",
		"unsupported keyword":         "profile_extensions: [a]\nprofile_extension_schemas: {a: {type: object, minProperties: 1}}\n",
		"missing schema file":         "profile_extensions: [a]\nprofile_extension_schemas: {a: nowhere.json}\n",
		"repeated name":               "profile_extensions: [a, a]\n",
		"opaque spelt otherwise":      "profile_extensions: [a]\nprofile_extension_schemas: {a: Opaque}\n",
	} {
		if _, _, err := mustParse(t, scopeYAML+body).ProfileLoadOptions(dir); err == nil {
			t.Errorf("%s: ProfileLoadOptions accepted it", name)
		}
	}
}

// TestProfileLoadOptions_CursorTemplateIsDefaultOnly: until the cursor tool takes the same
// setting, cursor_file_template accepts only the default (spelled out or unset).
func TestProfileLoadOptions_CursorTemplateIsDefaultOnly(t *testing.T) {
	for body, ok := range map[string]bool{
		"": true,
		"cursor_file_template: \"" + profile.DefaultCursorTemplate + "\"\n": true,
		"cursor_file_template: \"{root}/state/{agent_key}/memo.json\"\n":    false,
		"cursor_file_template: /abs/{agent_key}/c.json\n":                   false,
	} {
		opts, _, err := mustParse(t, scopeYAML+body).ProfileLoadOptions(t.TempDir())
		if (err == nil) != ok {
			t.Errorf("%q: err = %v, want ok=%v", body, err, ok)
		}
		if err == nil && opts.CursorTemplate.String() != profile.DefaultCursorTemplate {
			t.Errorf("%q: template %v", body, opts.CursorTemplate)
		}
	}
}
