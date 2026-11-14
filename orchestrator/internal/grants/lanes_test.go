// SPDX-License-Identifier: Apache-2.0

package grants

import (
	"errors"
	"testing"
)

// laneCatalogYAML is a fictional catalog exercising every lane binding.
const laneCatalogYAML = `kinds:
  notes:
    command: /usr/local/bin/notes-mcp
    allowed_env: [NOTES_ROOT, NOTES_WRITABLE_PREFIXES, NOTES_FINDINGS_PREFIX]
    allowed_values:
      NOTES_ROOT: [/srv/notes, /srv/checkout]
    profile_scope:
      root_key: NOTES_ROOT
      scope_roots: [/srv/notes]
      writable: [NOTES_WRITABLE_PREFIXES]
      prefix: [NOTES_FINDINGS_PREFIX]
      lane_shared: [inbox/]
  queue:
    command: /usr/local/bin/queue-mcp
    allowed_env: [QUEUE_BY, QUEUE_HOME, QUEUE_SEED_FROM, QUEUE_STATE_FILE]
    allowed_values:
      QUEUE_HOME: [/srv/notes, /srv/notes-shadow/watcher, /srv/notes-shadow/other-agent, /srv/other]
      QUEUE_SEED_FROM: [/srv/notes]
      QUEUE_STATE_FILE: [/srv/notes-shadow/watcher/.state.json, /srv/notes-shadow/other-agent/.state.json]
    profile_scope:
      agent_key_lane: [QUEUE_BY]
      shadow_only: [QUEUE_SEED_FROM]
      lane_home:
        equal: [QUEUE_HOME]
        within: [QUEUE_STATE_FILE]
        real: [/srv/notes]
        shadow_bases: [/srv/notes-shadow]
  store:
    command: /usr/local/bin/store-mcp
    allowed_env: [STORE_MODE, STORE_STATE_PATH]
    allowed_values:
      STORE_STATE_PATH: [/srv/cache/store-state.json, /srv/cache/store-state-shadow.json]
    profile_scope:
      lane_value: [STORE_MODE]
      lane_marked: [STORE_STATE_PATH]
`

var laneOwner = Owner{
	AgentKey:         "watcher",
	WritablePrefixes: []string{"notes/findings/watch/", "notes/findings/watch-shadow/", "notes/state/watch/", "notes/state/watch-shadow/", "inbox/"},
}

// A profile whose scope is broad still cannot grant a real-lane entry over its shadow dirs.
var broadOwner = Owner{AgentKey: "watcher", WritablePrefixes: []string{"notes/findings/", "notes/findings/watch-shadow/"}}

func onLane(o Owner, shadow bool) Owner { o.Shadow = shadow; return o }

type laneCase struct {
	shadow bool
	kind   string
	env    map[string]string
}

func TestRender_LanesAcceptEachLanesOwnValues(t *testing.T) {
	c := parse(t, laneCatalogYAML)
	for _, tc := range []laneCase{
		{false, "notes", map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch/,notes/state/watch/,inbox/", "NOTES_FINDINGS_PREFIX": "notes/findings/watch/"}},
		{true, "notes", map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch-shadow/,notes/state/watch-shadow/,inbox/", "NOTES_FINDINGS_PREFIX": "notes/findings/watch-shadow/"}},
		{true, "notes", map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch-shadow/sub/", "NOTES_FINDINGS_PREFIX": "notes/findings/watch-shadow/sub/"}},
		// a checkout root grants no writes, so a findings prefix there is inert
		{false, "notes", map[string]string{"NOTES_ROOT": "/srv/checkout", "NOTES_FINDINGS_PREFIX": "notes/findings/other/"}},
		{true, "notes", map[string]string{"NOTES_ROOT": "/srv/checkout", "NOTES_FINDINGS_PREFIX": "notes/findings/other/"}},
		{false, "queue", map[string]string{"QUEUE_BY": "watcher", "QUEUE_HOME": "/srv/notes"}},
		{true, "queue", map[string]string{"QUEUE_BY": "watcher-shadow", "QUEUE_HOME": "/srv/notes-shadow/watcher", "QUEUE_SEED_FROM": "/srv/notes", "QUEUE_STATE_FILE": "/srv/notes-shadow/watcher/.state.json"}},
		{false, "store", map[string]string{"STORE_MODE": "real", "STORE_STATE_PATH": "/srv/cache/store-state.json"}},
		{true, "store", map[string]string{"STORE_MODE": "shadow", "STORE_STATE_PATH": "/srv/cache/store-state-shadow.json"}},
	} {
		if _, err := c.Render([]Grant{{Name: "x", Kind: tc.kind, Env: tc.env}}, onLane(laneOwner, tc.shadow)); err != nil {
			t.Errorf("%s shadow=%v %v: %v", tc.kind, tc.shadow, tc.env, err)
		}
	}
}

// A shadow grant writing the real findings dir, a shadow queue pointed at the real store, a real
// queue pointed at another agent's shadow home, and the like.
func TestRender_LanesRefuseCrossingLanes(t *testing.T) {
	c := parse(t, laneCatalogYAML)
	for name, tc := range map[string]laneCase{
		"shadow writes the real findings dir":   {true, "notes", map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch/"}},
		"shadow writes real state":              {true, "notes", map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch-shadow/,notes/state/watch/"}},
		"shadow findings prefix is real":        {true, "notes", map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch-shadow/", "NOTES_FINDINGS_PREFIX": "notes/findings/watch/"}},
		"real writes a shadow dir":              {false, "notes", map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch-shadow/"}},
		"real findings prefix is shadow":        {false, "notes", map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch/", "NOTES_FINDINGS_PREFIX": "notes/findings/watch-shadow/"}},
		"findings prefix outside the writables": {false, "notes", map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "inbox/", "NOTES_FINDINGS_PREFIX": "notes/findings/watch/"}},
		"findings prefix with no writables":     {false, "notes", map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_FINDINGS_PREFIX": "notes/findings/watch/"}},
		"real entry spans the shadow dir":       {false, "notes", map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/"}},
		"shadow queue on the real store":        {true, "queue", map[string]string{"QUEUE_BY": "watcher-shadow", "QUEUE_HOME": "/srv/notes"}},
		"shadow queue in a peer's home":         {true, "queue", map[string]string{"QUEUE_BY": "watcher-shadow", "QUEUE_HOME": "/srv/notes-shadow/other-agent"}},
		"real queue in a peer's shadow home":    {false, "queue", map[string]string{"QUEUE_BY": "watcher", "QUEUE_HOME": "/srv/notes-shadow/other-agent"}},
		"real queue in its own shadow home":     {false, "queue", map[string]string{"QUEUE_BY": "watcher", "QUEUE_HOME": "/srv/notes-shadow/watcher"}},
		"real queue elsewhere":                  {false, "queue", map[string]string{"QUEUE_BY": "watcher", "QUEUE_HOME": "/srv/other"}},
		"real queue seeds itself":               {false, "queue", map[string]string{"QUEUE_BY": "watcher", "QUEUE_HOME": "/srv/notes", "QUEUE_SEED_FROM": "/srv/notes"}},
		"shadow state file in a peer's home":    {true, "queue", map[string]string{"QUEUE_BY": "watcher-shadow", "QUEUE_HOME": "/srv/notes-shadow/watcher", "QUEUE_STATE_FILE": "/srv/notes-shadow/other-agent/.state.json"}},
		"real state file in a shadow home":      {false, "queue", map[string]string{"QUEUE_BY": "watcher", "QUEUE_STATE_FILE": "/srv/notes-shadow/watcher/.state.json"}},
		"shadow lane in real mode":              {true, "store", map[string]string{"STORE_MODE": "real"}},
		"real lane in shadow mode":              {false, "store", map[string]string{"STORE_MODE": "shadow"}},
		"mode spelled otherwise":                {false, "store", map[string]string{"STORE_MODE": "Real"}},
		"shadow lane, real state path":          {true, "store", map[string]string{"STORE_MODE": "shadow", "STORE_STATE_PATH": "/srv/cache/store-state.json"}},
		"real lane, shadow state path":          {false, "store", map[string]string{"STORE_MODE": "real", "STORE_STATE_PATH": "/srv/cache/store-state-shadow.json"}},
		"shadow entry inside the real dir":      {true, "notes", map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch/-shadow/"}},
		"shadow dotted entry inside real dir":   {true, "notes", map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch/x.shadow/"}},
		"shadow segment inside the real dir":    {true, "notes", map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch/shadow/"}},
	} {
		if _, err := c.Render([]Grant{{Name: "x", Kind: tc.kind, Env: tc.env}}, onLane(laneOwner, tc.shadow)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	if _, err := c.Render([]Grant{{Name: "x", Kind: "notes", Env: map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/"}}}, broadOwner); !errors.Is(err, ErrInvalid) {
		t.Errorf("a broad real-lane entry spanning a shadow prefix rendered: %v", err)
	}
	if _, err := c.Render([]Grant{{Name: "x", Kind: "notes", Env: map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch/"}}}, broadOwner); err != nil {
		t.Errorf("a narrow real-lane entry under a broad scope: %v", err)
	}
	// A shadow home is derived from the agent key, so a key that is not a plain name has none.
	odd := onLane(laneOwner, true)
	odd.AgentKey = "../watcher"
	if _, err := c.Render([]Grant{{Name: "x", Kind: "queue", Env: map[string]string{"QUEUE_HOME": "/srv/notes-shadow/watcher"}}}, odd); !errors.Is(err, ErrInvalid) {
		t.Errorf("odd agent key got a shadow home: %v", err)
	}
}

func TestLoadCatalog_LaneBindingsMustBeWellFormed(t *testing.T) {
	refused(t, map[string]string{
		"lane-checked key not pinned": "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_STATE_PATH]\n    allowed_values: {}\n    profile_scope: {lane_marked: [K_STATE_PATH]}\n",
		"lane value also pinned":      "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_MODE]\n    allowed_values: {K_MODE: [real]}\n    profile_scope: {lane_value: [K_MODE]}\n",
		"lane home without homes":     "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_HOME]\n    allowed_values: {K_HOME: [/a]}\n    profile_scope: {lane_home: {equal: [K_HOME]}}\n",
		"lane home relative":          "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_HOME]\n    allowed_values: {K_HOME: [/a]}\n    profile_scope: {lane_home: {equal: [K_HOME], real: [a], shadow_bases: [/b]}}\n",
		"shared prefix is shadow":     "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_WRITABLE_PREFIXES, K_ROOT]\n    allowed_values: {K_ROOT: [/a]}\n    profile_scope: {root_key: K_ROOT, scope_roots: [/a], writable: [K_WRITABLE_PREFIXES], lane_shared: [x-shadow/]}\n",
		"shared prefix in owner":      "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_WRITABLE_PREFIXES, K_ROOT]\n    allowed_values: {K_ROOT: [/a]}\n    profile_scope: {root_key: K_ROOT, scope_roots: [/a], writable: [K_WRITABLE_PREFIXES], lane_shared: [owner/]}\n",
	})
}

// shadowReqCatalogYAML is a fictional collector kind whose scripts fall back to real-lane state
// when their lane key is unset.
const shadowReqCatalogYAML = `kinds:
  collect:
    command: /usr/local/bin/collect-mcp
    allowed_env: [RUN_SCRIPT_PATH, TREND_HISTORY_FILE, CACHE_STATE_PATH, REVIEW_SHADOW, RUN_NAME]
    allowed_values:
      RUN_SCRIPT_PATH: [/usr/local/libexec/trend.py, /usr/local/libexec/import.py, /usr/local/libexec/plain.py]
      TREND_HISTORY_FILE: [/srv/state/trend/history.jsonl, /srv/state/trend-shadow/history.jsonl]
      CACHE_STATE_PATH: [/srv/cache/import_state.json, /srv/cache/import_state-shadow.json]
      REVIEW_SHADOW: ['1']
    free_env: {RUN_NAME: name}
    profile_scope:
      lane_marked: [TREND_HISTORY_FILE, CACHE_STATE_PATH]
      shadow_only: [REVIEW_SHADOW]
      shadow_required:
        RUN_SCRIPT_PATH:
          /usr/local/libexec/trend.py: [TREND_HISTORY_FILE]
          /usr/local/libexec/import.py: [CACHE_STATE_PATH, REVIEW_SHADOW]
`

// A lane-marked key is checked only when present, so shadow_required makes each such key
// mandatory per script.
func TestRender_ShadowRequiredKeysPerScript(t *testing.T) {
	c := parse(t, shadowReqCatalogYAML)
	render := func(shadow bool, env map[string]string) error {
		_, err := c.Render([]Grant{{Name: "x", Kind: "collect", Env: env}}, onLane(laneOwner, shadow))
		return err
	}
	for name, tc := range map[string]laneCase{
		"shadow trend with its history":     {true, "", map[string]string{"RUN_SCRIPT_PATH": "/usr/local/libexec/trend.py", "TREND_HISTORY_FILE": "/srv/state/trend-shadow/history.jsonl"}},
		"shadow import with state + switch": {true, "", map[string]string{"RUN_SCRIPT_PATH": "/usr/local/libexec/import.py", "CACHE_STATE_PATH": "/srv/cache/import_state-shadow.json", "REVIEW_SHADOW": "1"}},
		"shadow script requiring nothing":   {true, "", map[string]string{"RUN_SCRIPT_PATH": "/usr/local/libexec/plain.py"}},
		"real trend may use the default":    {false, "", map[string]string{"RUN_SCRIPT_PATH": "/usr/local/libexec/trend.py"}},
		"real import with the real state":   {false, "", map[string]string{"RUN_SCRIPT_PATH": "/usr/local/libexec/import.py", "CACHE_STATE_PATH": "/srv/cache/import_state.json"}},
		"real import with no state key":     {false, "", map[string]string{"RUN_SCRIPT_PATH": "/usr/local/libexec/import.py"}},
	} {
		if err := render(tc.shadow, tc.env); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, tc := range map[string]laneCase{
		"shadow trend without history":     {true, "", map[string]string{"RUN_SCRIPT_PATH": "/usr/local/libexec/trend.py", "RUN_NAME": "trend-shadow"}},
		"shadow import without state":      {true, "", map[string]string{"RUN_SCRIPT_PATH": "/usr/local/libexec/import.py", "REVIEW_SHADOW": "1"}},
		"shadow import without the switch": {true, "", map[string]string{"RUN_SCRIPT_PATH": "/usr/local/libexec/import.py", "CACHE_STATE_PATH": "/srv/cache/import_state-shadow.json"}},
		"real import with the switch":      {false, "", map[string]string{"RUN_SCRIPT_PATH": "/usr/local/libexec/import.py", "REVIEW_SHADOW": "1"}},
		"shadow trend, real history":       {true, "", map[string]string{"RUN_SCRIPT_PATH": "/usr/local/libexec/trend.py", "TREND_HISTORY_FILE": "/srv/state/trend/history.jsonl"}},
	} {
		if err := render(tc.shadow, tc.env); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func TestLoadCatalog_ShadowRequiredMustBeWellFormed(t *testing.T) {
	head := "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_SCRIPT_PATH, K_STATE_PATH, K_OTHER_PATH]\n    allowed_values: {K_SCRIPT_PATH: [/a.py], K_STATE_PATH: [/s-shadow.json], K_OTHER_PATH: [/o]}\n    profile_scope:\n      lane_marked: [K_STATE_PATH]\n"
	parse(t, head+"      shadow_required: {K_SCRIPT_PATH: {/a.py: [K_STATE_PATH]}}\n")
	refused(t, map[string]string{
		"anchor not pinned":    head + "      shadow_required: {K_NOPE_PATH: {/a.py: [K_STATE_PATH]}}\n",
		"value not a pin":      head + "      shadow_required: {K_SCRIPT_PATH: {/b.py: [K_STATE_PATH]}}\n",
		"key not a lane key":   head + "      shadow_required: {K_SCRIPT_PATH: {/a.py: [K_OTHER_PATH]}}\n",
		"requires nothing":     head + "      shadow_required: {K_SCRIPT_PATH: {/a.py: []}}\n",
		"anchor is a lane key": head + "      shadow_required: {K_STATE_PATH: {/s-shadow.json: [K_STATE_PATH]}}\n",
	})
}
