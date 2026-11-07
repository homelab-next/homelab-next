// SPDX-License-Identifier: Apache-2.0

package grants

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/homelab-next/homelab-next/orchestrator/internal/pathscope"
)

// testZones is a fictional tree: owner/ is never writable, findings live under notes/findings/,
// and every lane writes inbox/.
var testZones = mustZones(pathscope.Zones{
	DeniedRoots:   []string{"owner"},
	FindingsRoot:  "notes/findings/",
	SharedWrite:   []string{"inbox/"},
	ReservedNames: []string{"operator"},
})

func mustZones(z pathscope.Zones) pathscope.Zones {
	v, err := pathscope.NewZones(z)
	if err != nil {
		panic(err)
	}
	return v
}

// parse is ParseCatalog over testZones, failing the test on an error.
func parse(t *testing.T, body string) *Catalog {
	t.Helper()
	c, err := ParseCatalog([]byte(body), testZones)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// refused asserts that each catalog body fails to load.
func refused(t *testing.T, bodies map[string]string) {
	t.Helper()
	for name, body := range bodies {
		if _, err := ParseCatalog([]byte(body), testZones); err == nil {
			t.Errorf("%s: catalog must not load", name)
		}
	}
}

const testCatalogYAML = `kinds:
  notes:
    command: /usr/local/bin/notes-mcp
    env: {NOTES_TIER: local}
    allowed_env: [NOTES_ROOT, NOTES_WRITABLE_PREFIXES]
    allowed_values: {NOTES_ROOT: [/srv/notes]}
    profile_scope: {root_key: NOTES_ROOT, scope_roots: [/srv/notes], writable: [NOTES_WRITABLE_PREFIXES]}
  collector:
    command: /usr/local/bin/collector-mcp
    timeout: 150
    allowed_env: [COLLECTOR_NAME]
    free_env: {COLLECTOR_NAME: name}
`

// ownerA is the profile the shared test grants belong to.
var ownerA = Owner{AgentKey: "agent-a", WritablePrefixes: []string{"notes/findings/a/"}}

func TestRender_OnlyGrantedServersWithCatalogCommandAndMergedEnv(t *testing.T) {
	c := parse(t, testCatalogYAML)
	out, err := c.Render([]Grant{
		{Name: "notes-a", Kind: "notes", Env: map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/a/"}},
		{Name: "collector-a", Kind: "collector", Env: map[string]string{"COLLECTOR_NAME": "a"}, Timeout: 30},
	}, ownerA)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want exactly the 2 granted servers, got %v", out)
	}
	v := out["notes-a"]
	if v.Command != "/usr/local/bin/notes-mcp" {
		t.Errorf("command must come from the catalog, got %v", v.Command)
	}
	if v.Env["NOTES_TIER"] != "local" || v.Env["NOTES_ROOT"] != "/srv/notes" {
		t.Errorf("env not merged: %v", v.Env)
	}
	if v.Timeout != 0 {
		t.Errorf("no timeout expected, got %v", v.Timeout)
	}
	if out["collector-a"].Timeout != 30 {
		t.Errorf("grant timeout should win, got %v", out["collector-a"].Timeout)
	}
	out2, err := c.Render([]Grant{{Name: "c", Kind: "collector"}}, ownerA)
	if err != nil || out2["c"].Timeout != 150 || out2["c"].Env != nil {
		t.Errorf("kind timeout should apply and an empty env stay nil: %+v, %v", out2["c"], err)
	}
}

func TestRender_FailsClosed(t *testing.T) {
	c := parse(t, testCatalogYAML)
	cases := map[string][]Grant{
		"unknown kind":            {{Name: "x", Kind: "nope"}},
		"env not allowed":         {{Name: "x", Kind: "notes", Env: map[string]string{"NOTES_AGENT_KEY": "a"}}},
		"fixed env overridden":    {{Name: "x", Kind: "notes", Env: map[string]string{"NOTES_TIER": "cloud"}}},
		"code-changing env":       {{Name: "x", Kind: "notes", Env: map[string]string{"LD_PRELOAD": "/tmp/x.so"}}},
		"duplicate server":        {{Name: "x", Kind: "notes"}, {Name: "x", Kind: "collector"}},
		"bad server name":         {{Name: "../x", Kind: "notes"}},
		"empty server name":       {{Name: "", Kind: "notes"}},
		"uppercase server name":   {{Name: "Notes", Kind: "notes"}},
		"name with a space":       {{Name: "notes a", Kind: "notes"}},
		"name with a comma":       {{Name: "a,b", Kind: "notes"}},
		"name with a slash":       {{Name: "a/b", Kind: "notes"}},
		"name with a newline":     {{Name: "a\nb", Kind: "notes"}},
		"name too long":           {{Name: strings.Repeat("a", 65), Kind: "notes"}},
		"dotted kind name":        {{Name: "x", Kind: "notes.mcp"}},
		"denied PATH in grant":    {{Name: "x", Kind: "collector", Env: map[string]string{"PATH": "/tmp"}}},
		"denied HOME in grant":    {{Name: "x", Kind: "collector", Env: map[string]string{"HOME": "/tmp"}}},
		"a ${VAR} in a value":     {{Name: "x", Kind: "collector", Env: map[string]string{"COLLECTOR_NAME": "${API_KEY}"}}},
		"free value off shape":    {{Name: "x", Kind: "collector", Env: map[string]string{"COLLECTOR_NAME": "../x"}}},
		"lower-case denied key":   {{Name: "x", Kind: "notes", Env: map[string]string{"node_options": "--require=/x"}}},
		"writes the owner zone":   {{Name: "x", Kind: "notes", Env: map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "owner/"}}},
		"pinned root off its pin": {{Name: "x", Kind: "notes", Env: map[string]string{"NOTES_ROOT": "/srv/other"}}},
	}
	for name, gs := range cases {
		if _, err := c.Render(gs, ownerA); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

// A catalog needs validated zones: without them no scope rule could be decided, so it is refused
// whole; and a Catalog built in code (no zones) refuses every grant that sets a scope key.
func TestCatalogNeedsValidatedZones(t *testing.T) {
	if _, err := ParseCatalog([]byte(testCatalogYAML), pathscope.Zones{DeniedRoots: []string{"owner"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unvalidated zones: %v", err)
	}
	direct := &Catalog{Kinds: parse(t, testCatalogYAML).Kinds}
	_, err := direct.Render([]Grant{{Name: "n", Kind: "notes", Env: map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/a/"}}}, ownerA)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("a catalog without zones rendered a scoped grant: %v", err)
	}
	if _, err := direct.Render([]Grant{{Name: "c", Kind: "collector"}}, ownerA); err != nil {
		t.Errorf("an unscoped grant needs no zones: %v", err)
	}
}

func TestLoadCatalog(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(testCatalogYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCatalog(p, testZones); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCatalog(filepath.Join(t.TempDir(), "missing.yaml"), testZones); err == nil {
		t.Fatal("a missing catalog loaded")
	}
	refused(t, map[string]string{
		"code-changing key grantable": "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [PYTHONPATH]\n",
		"unknown field":               "kinds:\n  k:\n    command: /bin/k\n    surprise: 1\n",
		"no command":                  "kinds:\n  k:\n    args: [x]\n",
		"bad kind name":               "kinds:\n  K.x:\n    command: /bin/k\n",
		"unknown top-level key":       "kinds: {}\nservers: {}\n",
		"repeated kind":               "kinds:\n  k:\n    command: /bin/k\n  k:\n    command: /bin/j\n",
		"pin for an unlisted key":     "kinds:\n  k:\n    command: /bin/k\n    allowed_values: {K_MODE: [a]}\n",
	})
}

func TestNamesAndLanes(t *testing.T) {
	if got := strings.Join(Names([]Grant{{Name: "notes-a"}, {Name: "collector-a"}, {Name: "web"}}), ","); got != "collector-a,notes-a,web" {
		t.Fatalf("got %q", got)
	}
	if !(Set{}).IsZero() || (Set{Shadow: []Grant{{Name: "x"}}}).IsZero() {
		t.Fatal("IsZero wrong")
	}
	s := Set{Real: []Grant{{Name: "r", Env: map[string]string{"A": "1"}}}, Shadow: []Grant{{Name: "s"}}}
	if s.Lane(true)[0].Name != "s" || s.Lane(false)[0].Name != "r" {
		t.Fatal("Lane picks the wrong list")
	}
	if err := s.Validate(); err != nil {
		t.Errorf("both lanes granted: %v", err)
	}
	if err := (Set{}).Validate(); err != nil {
		t.Errorf("no grants: %v", err)
	}
	for _, one := range []Set{{Real: s.Real}, {Shadow: s.Shadow}} {
		if err := one.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("one lane only (%+v): %v", one, err)
		}
	}
	cp := s.Clone()
	cp.Real[0].Env["A"] = "2"
	if s.Real[0].Env["A"] != "1" {
		t.Fatal("Clone shares an env map")
	}
}

// The grants block decodes strictly wherever it is embedded, and refuses a ${...} reference.
func TestSetDecodesStrictly(t *testing.T) {
	for name, body := range map[string]string{
		"lane typo":  "reall: [{name: v, kind: notes}]\n",
		"field typo": "real: [{name: v, knd: notes}]\n",
		"env typo":   "real: [{name: v, kind: notes, evn: {A: b}}]\n",
		"reference":  "real: [{name: v, kind: notes, env: {A: \"${SECRET}\"}}]\n",
	} {
		var s Set
		if err := yaml.Unmarshal([]byte(body), &s); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	var s Set
	if err := yaml.Unmarshal([]byte("real: [{name: v, kind: notes, env: {A: $b}, timeout: 5}]\nshadow: []\n"), &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Real) != 1 || s.Real[0].Env["A"] != "$b" || s.Real[0].Timeout != 5 {
		t.Errorf("decoded %+v", s)
	}
}

// The deny list: the loader, the interpreters, the package launchers, git, XDG config dirs, the
// container CLI's own settings, the TLS stack, proxies, the C library's knobs and the shell's, in
// any case, since a lower-case key reaches the same process on a case-insensitive lookup.
func TestDeniedEnv(t *testing.T) {
	for _, k := range []string{
		"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PATH", "Path", "HOME", "SHELL", "BASH_ENV", "ENV",
		"PYTHONPATH", "PYTHONWARNINGS", "NODE", "NODE_OPTIONS", "NODE_PATH", "NPM_CONFIG_PREFIX",
		"NPM_TOKEN", "UV_INDEX_URL", "PIP_INDEX_URL", "PIPX_HOME", "BUN_INSTALL", "COREPACK_HOME",
		"YARN_RC_FILENAME", "PNPM_HOME", "GIT_SSH_COMMAND", "XDG_CONFIG_HOME", "CONTAINER_HOST",
		"BUILDKIT_HOST", "COMPOSE_FILE", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CERT_PATH",
		"DOCKER_TLS_VERIFY", "DOCKER_CONTEXT", "DOCKER_API_VERSION", "DOCKER_DEFAULT_PLATFORM",
		"DOCKER_CONTENT_TRUST", "DOCKER_CLI_HINTS", "DOCKER_BUILDKIT", "DOCKER_CUSTOM_HEADERS",
		"OPENSSL_CONF", "OPENSSL_MODULES", "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE",
		"MALLOC_ARENA_MAX", "BASH_FUNC_x%%", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
		"_PROXY", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GCONV_PATH", "LOCPATH", "NLSPATH",
		"HOSTALIASES", "RES_OPTIONS", "LOCALDOMAIN", "GLIBC_TUNABLES", "TZDIR", "JAVA_TOOL_OPTIONS",
		"_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "PERL5OPT", "PERL5LIB", "PERLLIB", "RUBYOPT", "RUBYLIB",
		"SHELLOPTS", "BASHOPTS", "PS4", " PATH ",
	} {
		for _, v := range []string{k, strings.ToLower(k)} {
			if !DeniedEnv(v) {
				t.Errorf("%q must be denied", v)
			}
		}
	}
	for _, k := range []string{
		"NOTES_ROOT", "DOCKER_CONTAINER", "COLLECTOR_NAME", "QUEUE_PYTHON", "MYPATH", "TZ", "tz",
		"MY_PROXY_HOST", "PROXY", "HTTP_PROXY_TIMEOUT", "OPENSSL", "SSL_CERT", "MALLOC", "PS4X",
		"LOCPATHS", "PERL5", "RUBY", "JAVA_HOME_EXAMPLE", "TZDIRS", "EXAMPLE-PROXY",
	} {
		if DeniedEnv(k) {
			t.Errorf("%q is a server setting and must not be denied", k)
		}
	}
}

// The fixed env a kind sets is held to the rules a grant's value meets.
func TestLoadCatalog_FixedEnvMeetsTheGrantRules(t *testing.T) {
	refused(t, map[string]string{
		"fixed writable in the owner zone": "kinds:\n  k:\n    command: /bin/k\n    env: {K_WRITABLE_PREFIXES: owner/}\n",
		"fixed writable, other case":       "kinds:\n  k:\n    command: /bin/k\n    env: {K_WRITABLE_PREFIXES: \"inbox/,Owner/approved/\"}\n",
		"fixed readable traversal":         "kinds:\n  k:\n    command: /bin/k\n    env: {K_READABLE_PREFIXES: ../x}\n",
		"fixed readable dotfile":           "kinds:\n  k:\n    command: /bin/k\n    env: {K_READABLE_PREFIXES: .git/}\n",
		"fixed write scope":                "kinds:\n  k:\n    command: /bin/k\n    env: {K_WRITE_SCOPE: /etc}\n",
		"fixed findings prefix":            "kinds:\n  k:\n    command: /bin/k\n    env: {K_FINDINGS_PREFIX: owner/approved/}\n",
		"fixed agent key":                  "kinds:\n  k:\n    command: /bin/k\n    env: {K_AGENT_KEY: some-agent}\n",
		"fixed queue identity":             "kinds:\n  k:\n    command: /bin/k\n    env: {K_QUEUE_BY: some-agent}\n",
		"fixed denied key":                 "kinds:\n  k:\n    command: /bin/k\n    env: {LD_PRELOAD: /tmp/x.so}\n",
		"fixed off its pins":               "kinds:\n  k:\n    command: /bin/k\n    env: {K_ROOT: /b}\n    allowed_env: [K_ROOT]\n    allowed_values: {K_ROOT: [/a]}\n",
		"fixed free off shape":             "kinds:\n  k:\n    command: /bin/k\n    env: {K_NAME: /x}\n    allowed_env: [K_NAME]\n    free_env: {K_NAME: name}\n",
		"fixed bound key":                  "kinds:\n  k:\n    command: /bin/k\n    env: {K_WRITABLE_PREFIXES: inbox/}\n    allowed_env: [K_WRITABLE_PREFIXES, K_ROOT]\n    allowed_values: {K_ROOT: [/a]}\n    profile_scope: {root_key: K_ROOT, scope_roots: [/a], writable: [K_WRITABLE_PREFIXES]}\n",
		"fixed lane value":                 "kinds:\n  k:\n    command: /bin/k\n    env: {K_MODE: real}\n    allowed_env: [K_MODE]\n    profile_scope: {lane_value: [K_MODE]}\n",
	})
	parse(t, "kinds:\n  k:\n    command: /bin/k\n    env: {K_ROOT: /srv/notes, K_READABLE_PREFIXES: \"inbox/,owner/approved/\", K_TIMEOUT: '60', K_TOKEN: '${HNX_SECRET_K}'}\n")
}

// Every allowed_env key must be pinned, profile-bound or free_env with a shape; the suffix rules
// only say which keys can never be free.
func TestLoadCatalog_EveryGrantSettableKeyIsClassified(t *testing.T) {
	refused(t, map[string]string{
		"unclassified mode":         "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_MODE]\n",
		"unclassified by":           "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_QUEUE_BY]\n",
		"free by":                   "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_QUEUE_BY]\n    free_env: {K_QUEUE_BY: name}\n",
		"free prefix list":          "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_PREFIX_LIST]\n    free_env: {K_PREFIX_LIST: name}\n",
		"free write scope":          "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_WRITE_SCOPE]\n    free_env: {K_WRITE_SCOPE: name}\n",
		"free read list":            "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_READ_LIST]\n    free_env: {K_READ_LIST: name}\n",
		"free path":                 "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_STATE_PATH]\n    free_env: {K_STATE_PATH: name}\n",
		"free agent key":            "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_AGENT_KEY]\n    free_env: {K_AGENT_KEY: name}\n",
		"unknown shape":             "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_NAME]\n    free_env: {K_NAME: anything}\n",
		"free key not allowed":      "kinds:\n  k:\n    command: /bin/k\n    free_env: {K_NAME: name}\n",
		"free and pinned":           "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_NAME]\n    allowed_values: {K_NAME: [a]}\n    free_env: {K_NAME: name}\n",
		"free and bound":            "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_MODE]\n    free_env: {K_MODE: name}\n    profile_scope: {lane_value: [K_MODE]}\n",
		"free denied key":           "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [NODE_OPTIONS]\n    free_env: {NODE_OPTIONS: name}\n",
		"unclassified label":        "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_AGENT_LABEL]\n",
		"unclassified prefix spelt": "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_PREFIX_SET]\n",
		"unbound writable prefixes": "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_WRITABLE_PREFIXES]\n",
		"unbound single prefix":     "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_FINDINGS_PREFIX]\n",
		"unpinned caller flag":      "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_CALLER_ARG_FLAG]\n",
		"unpinned caller pattern":   "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_CALLER_ARG_PATTERN]\n",
		"unpinned caller arg name":  "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_CALLER_ARG_NAME]\n",
		"bound key not allowed":     "kinds:\n  k:\n    command: /bin/k\n    profile_scope: {agent_key: [K_AGENT_KEY]}\n",
		"bound and pinned":          "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_AGENT_KEY]\n    allowed_values: {K_AGENT_KEY: [a]}\n    profile_scope: {agent_key: [K_AGENT_KEY]}\n",
		"writable without root":     "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_WRITABLE_PREFIXES]\n    profile_scope: {writable: [K_WRITABLE_PREFIXES]}\n",
		"unpinned root":             "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_WRITABLE_PREFIXES, K_MODE]\n    profile_scope: {root_key: K_MODE, scope_roots: [x], writable: [K_WRITABLE_PREFIXES]}\n",
		"scope root not pinned":     "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_WRITABLE_PREFIXES, K_ROOT]\n    allowed_values: {K_ROOT: [/a]}\n    profile_scope: {root_key: K_ROOT, scope_roots: [/b], writable: [K_WRITABLE_PREFIXES]}\n",
		"writable no scope roots":   "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_WRITABLE_PREFIXES, K_ROOT]\n    allowed_values: {K_ROOT: [/a]}\n    profile_scope: {root_key: K_ROOT, writable: [K_WRITABLE_PREFIXES]}\n",
		"set key not allowed":       "kinds:\n  k:\n    command: /bin/k\n    allowed_sets: [{K_CALLER_ARG_FLAG: --x}]\n",
		"set value off its pins":    "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_SCRIPT_PATH, K_CALLER_ARG_FLAG]\n    allowed_values: {K_SCRIPT_PATH: [/a]}\n    allowed_sets: [{K_SCRIPT_PATH: /b, K_CALLER_ARG_FLAG: --x}]\n",
		"empty set":                 "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_SCRIPT_PATH]\n    allowed_values: {K_SCRIPT_PATH: [/a]}\n    allowed_sets: [{}]\n",
		"set pins nothing new":      "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_SCRIPT_PATH]\n    allowed_values: {K_SCRIPT_PATH: [/a]}\n    allowed_sets: [{K_SCRIPT_PATH: /a}]\n",
		"verdict not a prefix key":  "kinds:\n  k:\n    command: /bin/k\n    env: {K_ROOT: /a}\n    allowed_env: [K_WRITABLE_PREFIXES, K_VERDICT_PREFIX]\n    profile_scope: {root_key: K_ROOT, scope_roots: [/a], writable: [K_WRITABLE_PREFIXES], verdict_prefix: [K_VERDICT_PREFIX]}\n",
		"bound twice":               "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_AGENT_KEY]\n    profile_scope: {agent_key: [K_AGENT_KEY], agent_key_lane: [K_AGENT_KEY]}\n",
		"root without scope keys":   "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_ROOT]\n    allowed_values: {K_ROOT: [/a]}\n    profile_scope: {root_key: K_ROOT}\n",
	})
	c := parse(t, "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_NAME, K_TIMEOUT_SECONDS, K_MODE, K_QUEUE_BY]\n    allowed_values: {K_MODE: [a, b]}\n    free_env: {K_NAME: name, K_TIMEOUT_SECONDS: int}\n    profile_scope: {agent_key_lane: [K_QUEUE_BY]}\n")
	render := func(env map[string]string) error {
		_, err := c.Render([]Grant{{Name: "k", Kind: "k", Env: env}}, Owner{AgentKey: "watcher"})
		return err
	}
	if err := render(map[string]string{"K_NAME": "probe-a", "K_TIMEOUT_SECONDS": "90", "K_MODE": "b", "K_QUEUE_BY": "watcher"}); err != nil {
		t.Fatal(err)
	}
	for _, env := range []map[string]string{
		{"K_NAME": "/srv/x"}, {"K_NAME": "a b"}, {"K_NAME": "A"}, {"K_NAME": "x\ny"}, {"K_NAME": ""},
		{"K_TIMEOUT_SECONDS": "0"}, {"K_TIMEOUT_SECONDS": "-1"}, {"K_TIMEOUT_SECONDS": "100000"}, {"K_TIMEOUT_SECONDS": "9s"},
		{"K_MODE": "c"},
	} {
		if err := render(env); !errors.Is(err, ErrInvalid) {
			t.Errorf("%v: want ErrInvalid, got %v", env, err)
		}
	}
	// A catalog built in code is held to the same rule at render time.
	direct := &Catalog{Kinds: map[string]Kind{"k": {Command: "/bin/k", AllowedEnv: []string{"K_ANYTHING"}}}}
	if _, err := direct.Render([]Grant{{Name: "k", Kind: "k", Env: map[string]string{"K_ANYTHING": "x"}}}, Owner{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("an unclassified key rendered: %v", err)
	}
}

// The grants a profile declares never reach a server the catalog does not define the same way for
// both lanes: a set-only key is used exactly as one listed set.
func TestRender_AllowedSetsTieCallerArgumentsToOneScript(t *testing.T) {
	c := parse(t, `kinds:
  runner:
    command: /usr/local/bin/runner-mcp
    allowed_env: [RUN_SCRIPT_PATH, RUN_CALLER_ARG_NAME, RUN_CALLER_ARG_FLAG, RUN_CALLER_ARG_PATTERN]
    allowed_values:
      RUN_SCRIPT_PATH: [/usr/local/libexec/a.py, /usr/local/libexec/b.py]
    allowed_sets:
    - RUN_SCRIPT_PATH: /usr/local/libexec/a.py
      RUN_CALLER_ARG_NAME: batch_id
      RUN_CALLER_ARG_FLAG: --batch-id
      RUN_CALLER_ARG_PATTERN: 'batch_\d{6}'
`)
	ok := map[string]string{"RUN_SCRIPT_PATH": "/usr/local/libexec/a.py", "RUN_CALLER_ARG_NAME": "batch_id", "RUN_CALLER_ARG_FLAG": "--batch-id", "RUN_CALLER_ARG_PATTERN": `batch_\d{6}`}
	run := func(env map[string]string) error {
		_, err := c.Render([]Grant{{Name: "r", Kind: "runner", Env: env}}, ownerA)
		return err
	}
	if err := run(ok); err != nil {
		t.Fatalf("the catalog's own set: %v", err)
	}
	if err := run(map[string]string{"RUN_SCRIPT_PATH": "/usr/local/libexec/b.py"}); err != nil {
		t.Fatalf("a script with no caller argument: %v", err)
	}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for kk, vv := range ok {
			m[kk] = vv
		}
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for name, env := range map[string]map[string]string{
		"any flag":                  with("RUN_CALLER_ARG_FLAG", "--out"),
		"match-anything pattern":    with("RUN_CALLER_ARG_PATTERN", ".*"),
		"set moved to b.py":         with("RUN_SCRIPT_PATH", "/usr/local/libexec/b.py"),
		"partial set":               with("RUN_CALLER_ARG_FLAG", ""),
		"caller arg with no script": {"RUN_CALLER_ARG_NAME": "batch_id", "RUN_CALLER_ARG_FLAG": "--batch-id", "RUN_CALLER_ARG_PATTERN": `batch_\d{6}`},
	} {
		if err := run(env); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}
