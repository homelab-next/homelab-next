// SPDX-License-Identifier: Apache-2.0

package profile

import "testing"

// TestCursorTemplate: the default template is the cursor tool's own store
// layout, a configured one moves it, and malformed templates are refused.
func TestCursorTemplate(t *testing.T) {
	var def CursorTemplate
	if got := def.String(); got != DefaultCursorTemplate {
		t.Fatalf("zero template = %q, want %q", got, DefaultCursorTemplate)
	}
	for path, want := range map[string]bool{
		"/srv/notes/agents/state/watcher/cursor.json":          true,
		"/srv/notes/agents/state/other/cursor.json":            false, // another agent's store
		"/srv/notes/agents/state/watcher-shadow/cursor.json":   false,
		"/srv/notes/agents/state/shared-state.json":            false,
		"/srv/notes/../notes/agents/state/watcher/cursor.json": false,
		"srv/agents/state/watcher/cursor.json":                 false,
		"/agents/state/watcher/cursor.json":                    false,
		"/srv//agents/state/watcher/cursor.json":               false,
	} {
		root, dir, name, ok := def.StoreAt(path, "watcher")
		if ok != want {
			t.Errorf("StoreAt(%q) ok = %v, want %v", path, ok, want)
		}
		if ok && (root != "/srv/notes" || dir != "agents/state/watcher" || name != "cursor.json") {
			t.Errorf("StoreAt(%q) = %q %q %q", path, root, dir, name)
		}
	}
	if _, _, _, ok := def.StoreAt("/srv/notes/agents/state/Bad_Key/cursor.json", "Bad_Key"); ok {
		t.Error("a non-canonical agent key must never own a store")
	}
	moved, err := ParseCursorTemplate("{root}/state/{agent_key}/memo.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := moved.StoreAt("/data/state/watcher/memo.json", "watcher"); !ok {
		t.Error("a configured template must locate its own layout")
	}
	if _, _, _, ok := moved.StoreAt("/srv/notes/agents/state/watcher/cursor.json", "watcher"); ok {
		t.Error("a configured template must not accept the default layout")
	}
	for _, bad := range []string{
		"agents/state/{agent_key}/cursor.json",
		"{root}/cursor.json",
		"{root}/agents/state/cursor.json",
		"{root}/agents/{agent_key}/{agent_key}/cursor.json",
		"{root}/agents/x{agent_key}/cursor.json",
		"{root}/agents/{agent_key}/{name}.json",
		"{root}/../{agent_key}/cursor.json",
		"{root}/agents/{agent_key}/",
	} {
		if _, err := ParseCursorTemplate(bad); err == nil {
			t.Errorf("ParseCursorTemplate(%q) accepted a malformed template", bad)
		}
	}
}
