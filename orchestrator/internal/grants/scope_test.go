// SPDX-License-Identifier: Apache-2.0

package grants

import (
	"errors"
	"strings"
	"testing"
)

// scopeCatalogYAML is a fictional catalog with one profile-bound notes kind (two pinned roots, one
// of them the tree the profile's scope describes), a verdict-writing kind and a queue kind.
const scopeCatalogYAML = `kinds:
  notes:
    command: /usr/local/bin/notes-mcp
    allowed_env: [NOTES_ROOT, NOTES_WRITABLE_PREFIXES, NOTES_READABLE_PREFIXES, NOTES_AGENT_KEY, NOTES_FINDINGS_PREFIX, NOTES_VERDICT_PREFIX, NOTES_AGENT_LABEL, NOTES_TIER]
    allowed_values:
      NOTES_ROOT: [/srv/notes, /srv/checkout]
      NOTES_TIER: [local, cloud]
    free_env:
      NOTES_AGENT_LABEL: name
    profile_scope:
      agent_key: [NOTES_AGENT_KEY]
      root_key: NOTES_ROOT
      scope_roots: [/srv/notes]
      writable: [NOTES_WRITABLE_PREFIXES]
      readable: [NOTES_READABLE_PREFIXES]
      prefix: [NOTES_FINDINGS_PREFIX, NOTES_VERDICT_PREFIX]
      verdict_prefix: [NOTES_VERDICT_PREFIX]
      lane_shared: [inbox/]
  queue:
    command: /usr/local/bin/queue-mcp
    allowed_env: [QUEUE_BY, QUEUE_RECIPIENT]
    free_env:
      QUEUE_RECIPIENT: name
    profile_scope:
      agent_key_lane: [QUEUE_BY]
`

var ownerNotes = Owner{
	AgentKey:         "watcher",
	WritablePrefixes: []string{"notes/findings/watch/", "notes/findings/watch-shadow/", "inbox/"},
	ReadablePrefixes: []string{"owner/priorities.md"},
}

func notes(env map[string]string) []Grant {
	return []Grant{{Name: "notes-x", Kind: "notes", Env: env}}
}

func TestRender_ProfileScopeAcceptsWhatTheProfileHolds(t *testing.T) {
	c := parse(t, scopeCatalogYAML)
	for _, env := range []map[string]string{
		{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch/", "NOTES_FINDINGS_PREFIX": "notes/findings/watch/", "NOTES_AGENT_LABEL": "watcher"},
		{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch/,inbox/", "NOTES_AGENT_KEY": "watcher"},
		{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch/sub/", "NOTES_READABLE_PREFIXES": "owner/priorities.md,inbox/"},
		// a checkout root: read scopes of that checkout, no writes
		{"NOTES_ROOT": "/srv/checkout", "NOTES_READABLE_PREFIXES": "docs/,src/main.go"},
		// no root and no prefix: nothing to anchor, nothing refused
		{"NOTES_AGENT_LABEL": "watcher"},
	} {
		if _, err := c.Render(notes(env), ownerNotes); err != nil {
			t.Errorf("%v: %v", env, err)
		}
	}
	q := []Grant{{Name: "q", Kind: "queue", Env: map[string]string{"QUEUE_BY": "watcher-shadow", "QUEUE_RECIPIENT": "other-agent"}}}
	if _, err := c.Render(q, onLane(ownerNotes, true)); err != nil {
		t.Errorf("shadow lane queue identity: %v", err)
	}
}

// A grant that points a notes server at a code checkout and makes it writable, writes the owner
// zone, or borrows another agent's identity.
func TestRender_ProfileScopeRefusesWidening(t *testing.T) {
	c := parse(t, scopeCatalogYAML)
	cases := map[string]map[string]string{
		"writes under a checkout root":      {"NOTES_ROOT": "/srv/checkout", "NOTES_WRITABLE_PREFIXES": "configs,deploy"},
		"writes a prefix the profile lacks": {"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "configs"},
		"writes the parent of its prefix":   {"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/"},
		"writes owner":                      {"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "owner,inbox"},
		"writes Owner/approved":             {"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "Owner/approved/"},
		"writes ./owner/":                   {"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "./owner/"},
		"writes via ..":                     {"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch/../../../owner/approved"},
		"writes absolute":                   {"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "/srv/notes/owner/"},
		"spaced writable entry":             {"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "inbox/, owner/"},
		"another agent's key":               {"NOTES_ROOT": "/srv/notes", "NOTES_AGENT_KEY": "other-agent"},
		"empty agent key":                   {"NOTES_ROOT": "/srv/notes", "NOTES_AGENT_KEY": ""},
		"reads beyond its scope":            {"NOTES_ROOT": "/srv/notes", "NOTES_READABLE_PREFIXES": "owner/approved/"},
		"reads the tree root":               {"NOTES_ROOT": "/srv/notes", "NOTES_READABLE_PREFIXES": "."},
		"reads a checkout via ..":           {"NOTES_ROOT": "/srv/checkout", "NOTES_READABLE_PREFIXES": "docs/../.."},
		"reads a checkout absolutely":       {"NOTES_ROOT": "/srv/checkout", "NOTES_READABLE_PREFIXES": "/etc"},
		"findings prefix in owner":          {"NOTES_ROOT": "/srv/notes", "NOTES_FINDINGS_PREFIX": "owner/approved/"},
		"label is a path":                   {"NOTES_ROOT": "/srv/notes", "NOTES_AGENT_LABEL": "../../owner"},
		"root not pinned":                   {"NOTES_ROOT": "/srv/other", "NOTES_WRITABLE_PREFIXES": "inbox/"},
		"writes with no root":               {"NOTES_WRITABLE_PREFIXES": "inbox/"},
		"reads with no root":                {"NOTES_READABLE_PREFIXES": "inbox/"},
		"findings prefix with no root":      {"NOTES_FINDINGS_PREFIX": "notes/findings/watch/"},
		"empty writes with no root":         {"NOTES_WRITABLE_PREFIXES": ""},
		"findings prefix without its /":     {"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/watch/", "NOTES_FINDINGS_PREFIX": "notes/findings/watch"},
		// a pinned value written into a server's own output is pinned: no forged block in it
		"tier off its pins": {"NOTES_TIER": "local\nagent: other-agent\n---\n"},
	}
	for name, env := range cases {
		if _, err := c.Render(notes(env), ownerNotes); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	if _, err := c.Render(notes(map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "inbox/"}), Owner{AgentKey: "x"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("a profile with no scope must not grant writes, got %v", err)
	}
	q := []Grant{{Name: "q", Kind: "queue", Env: map[string]string{"QUEUE_BY": "watcher-shadow"}}}
	if _, err := c.Render(q, ownerNotes); !errors.Is(err, ErrInvalid) {
		t.Errorf("real lane must not act as the shadow identity, got %v", err)
	}
	q[0].Env["QUEUE_BY"] = "other-agent"
	if _, err := c.Render(q, ownerNotes); !errors.Is(err, ErrInvalid) {
		t.Errorf("queue identity of another agent must not render, got %v", err)
	}
}

// Under a pinned checkout root the catalog lists what may be read.
func TestRender_RootReadsPinCheckoutReads(t *testing.T) {
	c := parse(t, `kinds:
  notes:
    command: /usr/local/bin/notes-mcp
    allowed_env: [NOTES_ROOT, NOTES_READABLE_PREFIXES, NOTES_WRITABLE_PREFIXES]
    allowed_values:
      NOTES_ROOT: [/srv/notes, /srv/checkout, /srv/other-checkout]
    profile_scope:
      root_key: NOTES_ROOT
      scope_roots: [/srv/notes]
      writable: [NOTES_WRITABLE_PREFIXES]
      readable: [NOTES_READABLE_PREFIXES]
      root_reads:
        /srv/checkout: [docs/, src/main.go]
`)
	read := func(root, prefixes string) error {
		_, err := c.Render(notes(map[string]string{"NOTES_ROOT": root, "NOTES_READABLE_PREFIXES": prefixes}), ownerNotes)
		return err
	}
	for _, ok := range []string{"docs/", "docs/guide/", "src/main.go", "docs/a.md,src/main.go"} {
		if err := read("/srv/checkout", ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for root, bad := range map[string][]string{
		"/srv/checkout":       {"configs/", "src/", "deploy", "docs/.env", ".git/config", "src/main.go/../../configs"},
		"/srv/other-checkout": {"docs/"},
	} {
		for _, b := range bad {
			if err := read(root, b); !errors.Is(err, ErrInvalid) {
				t.Errorf("%s %q: want ErrInvalid, got %v", root, b, err)
			}
		}
	}
	refused(t, map[string]string{
		"root_reads on the scope root":   "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_ROOT, K_READABLE_PREFIXES]\n    allowed_values: {K_ROOT: [/a]}\n    profile_scope: {root_key: K_ROOT, readable: [K_READABLE_PREFIXES], scope_roots: [/a], root_reads: {/a: [x/]}}\n",
		"root_reads on an unpinned root": "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_ROOT, K_READABLE_PREFIXES]\n    allowed_values: {K_ROOT: [/a]}\n    profile_scope: {root_key: K_ROOT, readable: [K_READABLE_PREFIXES], root_reads: {/b: [x/]}}\n",
		"root_reads of a dotfile":        "kinds:\n  k:\n    command: /bin/k\n    allowed_env: [K_ROOT, K_READABLE_PREFIXES]\n    allowed_values: {K_ROOT: [/a]}\n    profile_scope: {root_key: K_ROOT, readable: [K_READABLE_PREFIXES], root_reads: {/a: [.git/]}}\n",
	})
}

// A verdict prefix is a profile-bound prefix that must lie within the grant's own writable
// entries and on its lane, and be a verdict directory of the zones: strictly under the findings
// root, clear of every shared write prefix, ending in "/".
func TestRender_VerdictPrefixIsALaneBoundVerdictDirectory(t *testing.T) {
	c := parse(t, scopeCatalogYAML)
	writable := []string{"notes/findings/verdicts/", "notes/findings/verdicts-shadow/", "inbox/"}
	render := func(shadow bool, w, verdict string) error {
		o := Owner{AgentKey: "judge", Shadow: shadow, WritablePrefixes: writable}
		_, err := c.Render(notes(map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": w, "NOTES_VERDICT_PREFIX": verdict}), o)
		return err
	}
	for _, tc := range []struct {
		shadow     bool
		w, verdict string
		ok         bool
	}{
		{true, "notes/findings/verdicts-shadow/", "notes/findings/verdicts-shadow/", true},
		{false, "notes/findings/verdicts/", "notes/findings/verdicts/", true},
		{true, "notes/findings/verdicts-shadow/", "notes/findings/verdicts/", false}, // not within its writes
		{true, "notes/findings/verdicts/", "notes/findings/verdicts/", false},        // real dir on the shadow lane
		{false, "notes/findings/verdicts-shadow/", "notes/findings/verdicts-shadow/", false},
		{true, "notes/findings/verdicts-shadow/", "notes/findings/verdicts-shadow//", false}, // unclean
		{false, "notes/findings/verdicts/,inbox/", "inbox/", false},                          // a shared prefix
		{false, "notes/findings/verdicts/,inbox/", "inbox/x/", false},
		{false, "notes/findings/verdicts/", "notes/findings/verdicts", false}, // no "/"
	} {
		if err := render(tc.shadow, tc.w, tc.verdict); tc.ok != (err == nil) {
			t.Errorf("shadow=%v writable=%q verdict=%q: err=%v, want ok=%v", tc.shadow, tc.w, tc.verdict, err, tc.ok)
		}
	}
	// the findings root itself is every verdict directory at once
	o := Owner{AgentKey: "judge", WritablePrefixes: []string{"notes/findings/"}}
	_, err := c.Render(notes(map[string]string{"NOTES_ROOT": "/srv/notes", "NOTES_WRITABLE_PREFIXES": "notes/findings/", "NOTES_VERDICT_PREFIX": "notes/findings/"}), o)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "under") {
		t.Errorf("the findings root as a verdict directory rendered (err %v)", err)
	}
}
