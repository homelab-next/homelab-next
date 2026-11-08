// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writePCFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const pcStateFile = "/srv/notes/state.json"

// pcOptions is a controller config's prompt-context half: one prompt dir,
// one allowed state file, one facts command.
func pcOptions(promptDir string) LoadOptions {
	return LoadOptions{
		Zones:      testZones,
		PromptDir:  promptDir,
		StateFiles: []string{pcStateFile},
		FactsCommands: map[string]FactsCommand{
			"example": {Argv: []string{"/usr/local/bin/facts", "--json"}, Env: []string{"EXAMPLE_ENDPOINT"}},
		},
	}
}

// TestLoadRegistry_PromptContextResolvesFiles: appendix and preamble files
// are read at load from prompt_dir, with one trailing newline dropped; the
// lane lists stay separate; facts resolves to the catalog entry.
func TestLoadRegistry_PromptContextResolvesFiles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "profiles")
	prompt := filepath.Join(root, "prompt")
	writePCFile(t, filepath.Join(prompt, "all.md"), "[all]\n")
	writePCFile(t, filepath.Join(prompt, "real.md"), "[real]\n")
	writePCFile(t, filepath.Join(prompt, "lanes", "shadow.md"), "[shadow] line one\nline two\n")
	writePCFile(t, filepath.Join(prompt, "pre.md"), "[deterministic-facts] Example preamble.\n")
	writePCFile(t, filepath.Join(dir, "watcher.yaml"), `id: watcher-v1
agent_key: watcher
prompt_context:
  state_file: /srv/notes/state.json
  state_label: notes/state.json
  known_incidents_key: watcher
  cursor: true
  facts: example
  facts_timeout_s: 30
  facts_preamble_file: pre.md
  appendix_files: [all.md]
  real_appendix_files: [real.md]
  shadow_appendix_files: [lanes/shadow.md]
`)
	reg, err := LoadRegistry(dir, pcOptions(prompt))
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.Resolve("watcher")
	if err != nil {
		t.Fatal(err)
	}
	pc := p.PromptContext
	want := FactsCommand{Argv: []string{"/usr/local/bin/facts", "--json"}, Env: []string{"EXAMPLE_ENDPOINT"}}
	if pc.StateFile != pcStateFile || pc.Label() != "notes/state.json" || pc.KnownIncidentsKey != "watcher" ||
		!pc.Cursor || pc.FactsTimeoutS != 30 || pc.Facts != "example" || !reflect.DeepEqual(pc.FactsCommand, want) {
		t.Fatalf("prompt_context = %+v", pc)
	}
	if pc.FactsPreamble != "[deterministic-facts] Example preamble." {
		t.Errorf("FactsPreamble = %q", pc.FactsPreamble)
	}
	if got := pc.LaneAppendix(false); !reflect.DeepEqual(got, []string{"[all]", "[real]"}) {
		t.Errorf("real lane appendix = %q", got)
	}
	if got := pc.LaneAppendix(true); !reflect.DeepEqual(got, []string{"[all]", "[shadow] line one\nline two"}) {
		t.Errorf("shadow lane appendix = %q", got)
	}
	// Resolve returns an independent copy.
	p.PromptContext.Appendix[0] = "mutated"
	p.PromptContext.FactsCommand.Argv[0] = "mutated"
	p.PromptContext.FactsCommand.Env[0] = "mutated"
	again, _ := reg.Resolve("watcher")
	if again.PromptContext.Appendix[0] != "[all]" || !reflect.DeepEqual(again.PromptContext.FactsCommand, want) {
		t.Error("Resolve shares prompt_context slices with the registry")
	}
}

func TestPromptContext_LabelDefaultsToBaseName(t *testing.T) {
	if got := (PromptContext{StateFile: "/srv/notes/agents/state/state.json"}).Label(); got != "state.json" {
		t.Errorf("Label() = %q", got)
	}
}

// TestLoadRegistry_PromptContextRejectsBadBlocks: fail at load, never at a
// dispatch.
func TestLoadRegistry_PromptContextRejectsBadBlocks(t *testing.T) {
	for name, body := range map[string]string{
		"missing appendix":       "prompt_context: {appendix_files: [nope.md]}\n",
		"missing lane appendix":  "prompt_context: {shadow_appendix_files: [nope.md]}\n",
		"missing preamble":       "prompt_context: {facts: example, facts_preamble_file: nope.md}\n",
		"preamble without facts": "prompt_context: {facts_preamble_file: ok.md}\n",
		"timeout without facts":  "prompt_context: {facts_timeout_s: 5}\n",
		"cursor without state":   "prompt_context: {cursor: true}\n",
		"own_state w/o state":    "prompt_context: {own_state: true}\n",
		"incidents w/o state":    "prompt_context: {known_incidents_key: watcher}\n",
		"inject_own_state alone": "inject_own_state: true\n",
		"negative timeout":       "prompt_context: {facts: example, facts_timeout_s: -1}\n",
		"timeout above the cap":  "prompt_context: {facts: example, facts_timeout_s: 601}\n",
		"timeout overflowing":    "prompt_context: {facts: example, facts_timeout_s: 9223372036854775807}\n",
		"old facts_command key":  "prompt_context: {facts_command: [/usr/local/bin/facts]}\n",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			prompt := filepath.Join(root, "prompt")
			writePCFile(t, filepath.Join(prompt, "ok.md"), "ok\n")
			dir := filepath.Join(root, "profiles")
			writePCFile(t, filepath.Join(dir, "w.yaml"), "id: w-v1\nagent_key: w\n"+body)
			if _, err := LoadRegistry(dir, pcOptions(prompt)); err == nil {
				t.Fatal("LoadRegistry accepted a bad prompt_context")
			}
		})
	}
}

// TestLoadRegistry_ProfileCannotReachOutsideTheConfig: a profile can name only
// the facts commands, state files and prompt-dir files the controller config
// lists: no argv of its own, no absolute appendix, no ".." climb, no symlink
// out of (or inside) the prompt dir, and nothing at all with no config.
func TestLoadRegistry_ProfileCannotReachOutsideTheConfig(t *testing.T) {
	root := t.TempDir()
	prompt := filepath.Join(root, "prompt")
	writePCFile(t, filepath.Join(prompt, "ok.md"), "ok\n")
	outside := filepath.Join(root, "outside", "fake.env")
	writePCFile(t, outside, "EXAMPLE_KEY=not-for-prompts\n")
	if err := os.Symlink(outside, filepath.Join(prompt, "escape.md")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(prompt, "escapedir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("ok.md", filepath.Join(prompt, "inside.md")); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"argv in the profile":       "prompt_context: {facts_command: [sh, -c, \"echo KEY=$EXAMPLE_KEY\"]}\n",
		"unknown facts name":        "prompt_context: {facts: other}\n",
		"facts name case":           "prompt_context: {facts: Example}\n",
		"facts name space":          "prompt_context: {facts: \" example\"}\n",
		"absolute appendix":         "prompt_context: {appendix_files: [" + outside + "]}\n",
		"dotdot appendix":           "prompt_context: {appendix_files: [../outside/fake.env]}\n",
		"dotdot inside":             "prompt_context: {appendix_files: [sub/../ok.md]}\n",
		"deep dotdot":               "prompt_context: {real_appendix_files: [../../../../etc/passwd]}\n",
		"absolute preamble":         "prompt_context: {facts: example, facts_preamble_file: /etc/passwd}\n",
		"empty appendix name":       "prompt_context: {appendix_files: [\"\"]}\n",
		"symlink file escape":       "prompt_context: {shadow_appendix_files: [escape.md]}\n",
		"symlink dir escape":        "prompt_context: {appendix_files: [escapedir/fake.env]}\n",
		"symlink inside":            "prompt_context: {appendix_files: [inside.md]}\n",
		"state file not listed":     "prompt_context: {state_file: /srv/notes/other.json, cursor: true}\n",
		"state file relative":       "prompt_context: {state_file: srv/notes/state.json, cursor: true}\n",
		"state file case":           "prompt_context: {state_file: /srv/notes/State.json, cursor: true}\n",
		"state file dotdot":         "prompt_context: {state_file: /srv/notes/../secret/state.json, cursor: true}\n",
		"state file dotdot back in": "prompt_context: {state_file: /srv/other/../notes/state.json, cursor: true}\n",
		"state file dot":            "prompt_context: {state_file: /srv/notes/./state.json, cursor: true}\n",
		"inject_own_state unlisted": "inject_own_state: true\nprompt_context: {state_file: /srv/other.json}\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "profiles")
			writePCFile(t, filepath.Join(dir, "w.yaml"), "id: w-v1\nagent_key: w\n"+body)
			_, err := LoadRegistry(dir, pcOptions(prompt))
			if err == nil {
				t.Fatal("a profile reached outside the controller's prompt-context config")
			}
			t.Log(err)
		})
	}
	// With no prompt-context config at all, nothing is reachable, not even
	// what the configured case accepts.
	for name, body := range map[string]string{
		"facts":    "prompt_context: {facts: example}\n",
		"appendix": "prompt_context: {appendix_files: [ok.md]}\n",
		"state":    "prompt_context: {state_file: /srv/notes/state.json, cursor: true}\n",
	} {
		t.Run("plain "+name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "profiles")
			writePCFile(t, filepath.Join(dir, "w.yaml"), "id: w-v1\nagent_key: w\n"+body)
			if _, err := LoadRegistry(dir, plainOptions()); err == nil {
				t.Fatal("a load with no prompt-context config accepted a prompt_context reference")
			}
			if _, err := LoadRegistry(dir, pcOptions(prompt)); err != nil {
				t.Fatalf("the configured load must accept it: %v", err)
			}
		})
	}
}

// TestLoadOptions_BadCatalogFailsTheLoad: a malformed controller-side list
// fails every load, even when no profile uses it.
func TestLoadOptions_BadCatalogFailsTheLoad(t *testing.T) {
	prompt := t.TempDir()
	for name, mutate := range map[string]func(*LoadOptions){
		"relative argv0": func(o *LoadOptions) { o.FactsCommands["x"] = FactsCommand{Argv: []string{"bin/facts"}} },
		"empty argv":     func(o *LoadOptions) { o.FactsCommands["x"] = FactsCommand{} },
		"empty argv0":    func(o *LoadOptions) { o.FactsCommands["x"] = FactsCommand{Argv: []string{""}} },
		"empty name":     func(o *LoadOptions) { o.FactsCommands[""] = FactsCommand{Argv: []string{"/bin/true"}} },
		"bad env name": func(o *LoadOptions) {
			o.FactsCommands["x"] = FactsCommand{Argv: []string{"/bin/true"}, Env: []string{"A=B"}}
		},
		"empty env name": func(o *LoadOptions) {
			o.FactsCommands["x"] = FactsCommand{Argv: []string{"/bin/true"}, Env: []string{""}}
		},
		"wildcard env name": func(o *LoadOptions) {
			o.FactsCommands["x"] = FactsCommand{Argv: []string{"/bin/true"}, Env: []string{"*"}}
		},
		"space env name": func(o *LoadOptions) {
			o.FactsCommands["x"] = FactsCommand{Argv: []string{"/bin/true"}, Env: []string{" "}}
		},
		"lower env name": func(o *LoadOptions) {
			o.FactsCommands["x"] = FactsCommand{Argv: []string{"/bin/true"}, Env: []string{"example_endpoint"}}
		},
		"prefix env name": func(o *LoadOptions) {
			o.FactsCommands["x"] = FactsCommand{Argv: []string{"/bin/true"}, Env: []string{"LC_*"}}
		},
		"denied LD_PRELOAD": func(o *LoadOptions) {
			o.FactsCommands["x"] = FactsCommand{Argv: []string{"/bin/true"}, Env: []string{"LD_PRELOAD"}}
		},
		"denied PYTHONPATH": func(o *LoadOptions) {
			o.FactsCommands["x"] = FactsCommand{Argv: []string{"/bin/true"}, Env: []string{"PYTHONPATH"}}
		},
		"denied HTTPS_PROXY": func(o *LoadOptions) {
			o.FactsCommands["x"] = FactsCommand{Argv: []string{"/bin/true"}, Env: []string{"HTTPS_PROXY"}}
		},
		"argv0 dot":          func(o *LoadOptions) { o.FactsCommands["x"] = FactsCommand{Argv: []string{"."}} },
		"argv0 dotdot":       func(o *LoadOptions) { o.FactsCommands["x"] = FactsCommand{Argv: []string{".."}} },
		"argv0 ./x":          func(o *LoadOptions) { o.FactsCommands["x"] = FactsCommand{Argv: []string{"./facts"}} },
		"relative state":     func(o *LoadOptions) { o.StateFiles = []string{"state.json"} },
		"missing prompt dir": func(o *LoadOptions) { o.PromptDir = filepath.Join(prompt, "nope") },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writePCFile(t, filepath.Join(dir, "w.yaml"), "id: w-v1\nagent_key: w\n")
			opts := pcOptions(prompt)
			mutate(&opts)
			if _, err := LoadRegistry(dir, opts); err == nil {
				t.Fatal("a malformed controller-side list loaded")
			}
		})
	}
}

// TestLoadRegistry_FactsTimeoutBounds: 1..600 seconds load; the cap itself is accepted.
func TestLoadRegistry_FactsTimeoutBounds(t *testing.T) {
	for _, v := range []string{"1", "60", "600"} {
		root := t.TempDir()
		prompt := filepath.Join(root, "prompt")
		if err := os.MkdirAll(prompt, 0o755); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(root, "profiles")
		writePCFile(t, filepath.Join(dir, "w.yaml"), "id: w-v1\nagent_key: w\nprompt_context: {facts: example, facts_timeout_s: "+v+"}\n")
		if _, err := LoadRegistry(dir, pcOptions(prompt)); err != nil {
			t.Errorf("facts_timeout_s %s: %v", v, err)
		}
	}
}

// TestFactsCommand_EnvironIsScrubbed: only the base variables and the
// entry's own names pass; the controller's API keys never do.
func TestFactsCommand_EnvironIsScrubbed(t *testing.T) {
	environ := []string{"PATH=/usr/bin", "HOME=/home/example", "LANG=C.UTF-8", "LC_ALL=C", "TZ=UTC",
		"EXAMPLE_CREDENTIAL=not-for-prompts", "EXAMPLE_ENDPOINT=https://facts.example.internal", "PATHX=no", "=odd", "NOEQUALS"}
	got := FactsCommand{Argv: []string{"/bin/true"}, Env: []string{"EXAMPLE_ENDPOINT", "EXAMPLE_ABSENT"}}.Environ(environ)
	want := []string{"PATH=/usr/bin", "HOME=/home/example", "LANG=C.UTF-8", "LC_ALL=C", "TZ=UTC", "EXAMPLE_ENDPOINT=https://facts.example.internal"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Environ = %q, want %q", got, want)
	}
	if got := (FactsCommand{}).Environ(nil); got == nil || len(got) != 0 {
		t.Fatalf("an empty environment must be an empty, non-nil slice (nil would inherit everything): %#v", got)
	}
}

// TestLoadRegistry_OwnStateExcludesTheFactsBranch: rather than guess which
// block wins, a profile may not ask for both: own_state / inject_own_state with
// facts or known_incidents_key fails the load.
func TestLoadRegistry_OwnStateExcludesTheFactsBranch(t *testing.T) {
	prompt := t.TempDir()
	for name, body := range map[string]string{
		"inject_own_state + facts":      "inject_own_state: true\nprompt_context: {state_file: /srv/notes/state.json, facts: example}\n",
		"own_state + facts":             "prompt_context: {state_file: /srv/notes/state.json, own_state: true, facts: example}\n",
		"inject_own_state + incidents":  "inject_own_state: true\nprompt_context: {state_file: /srv/notes/state.json, known_incidents_key: w}\n",
		"own_state + incidents + facts": "prompt_context: {state_file: /srv/notes/state.json, own_state: true, known_incidents_key: w, facts: example}\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writePCFile(t, filepath.Join(dir, "w.yaml"), "id: w-v1\nagent_key: w\n"+body)
			_, err := LoadRegistry(dir, pcOptions(prompt))
			if err == nil || !strings.Contains(err.Error(), "own_state") {
				t.Fatalf("err = %v, want the own_state combination refused", err)
			}
		})
	}
}

// TestLoadRegistry_InjectOwnStateIsAnAlias: the older key turns on own_state.
func TestLoadRegistry_InjectOwnStateIsAnAlias(t *testing.T) {
	dir := t.TempDir()
	writePCFile(t, filepath.Join(dir, "w.yaml"), "id: w-v1\nagent_key: w\ninject_own_state: true\nprompt_context: {state_file: /srv/notes/state.json}\n")
	reg, err := LoadRegistry(dir, pcOptions(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := reg.Resolve("w")
	if !p.PromptContext.OwnState {
		t.Fatal("inject_own_state did not turn on prompt_context.own_state")
	}
}

// TestLoadRegistry_RevisionCoversPromptFiles: editing a referenced file, or
// the facts catalog entry a profile names, makes a new revision; a profile
// that references none hashes exactly as before (sha256 of the file bytes,
// first 12 hex).
func TestLoadRegistry_RevisionCoversPromptFiles(t *testing.T) {
	dir := t.TempDir()
	prompt := t.TempDir()
	plain := "id: p-v1\nagent_key: p\n"
	writePCFile(t, filepath.Join(dir, "p.yaml"), plain)
	writePCFile(t, filepath.Join(dir, "w.yaml"), "id: w-v1\nagent_key: w\nprompt_context: {appendix_files: [c.md], facts: example}\n")
	writePCFile(t, filepath.Join(prompt, "c.md"), "[contract] v1\n")
	opts := pcOptions(prompt)
	revs := func() (string, string) {
		reg, err := LoadRegistry(dir, opts)
		if err != nil {
			t.Fatal(err)
		}
		p, _ := reg.Resolve("p")
		w, _ := reg.Resolve("w")
		return p.Revision, w.Revision
	}
	p1, w1 := revs()
	if p1 != revisionOf([]byte(plain)) {
		t.Errorf("plain profile revision changed: %s", p1)
	}
	writePCFile(t, filepath.Join(prompt, "c.md"), "[contract] v2\n")
	p2, w2 := revs()
	if p2 != p1 {
		t.Error("an unrelated file changed a plain profile's revision")
	}
	if w2 == w1 || strings.TrimSpace(w2) == "" {
		t.Error("editing an appendix file did not change the profile revision")
	}
	opts.FactsCommands = map[string]FactsCommand{"example": {Argv: []string{"/usr/local/bin/facts", "--other"}}}
	if _, w3 := revs(); w3 == w2 {
		t.Error("changing the facts catalog entry did not change the profile revision")
	}
}

// TestLoadRegistry_CursorFile: cursor_file must be listed in prompt_state_files like state_file,
// and needs cursor: true; a listed one loads with its label.
func TestLoadRegistry_CursorFile(t *testing.T) {
	const store = "/srv/notes/agents/state/watcher/cursor.json"
	opts := pcOptions(t.TempDir())
	opts.StateFiles = append(opts.StateFiles, store)
	load := func(body string, o LoadOptions) (*Profile, error) {
		dir := t.TempDir()
		writePCFile(t, filepath.Join(dir, "watcher.yaml"), "id: watcher-v1\nagent_key: watcher\nprompt_context:\n  state_file: /srv/notes/state.json\n"+body)
		reg, err := LoadRegistry(dir, o)
		if err != nil {
			return nil, err
		}
		return reg.Resolve("watcher")
	}
	p, err := load("  cursor: true\n  cursor_file: "+store+"\n  cursor_label: agents/state/watcher/cursor.json\n", opts)
	if err != nil {
		t.Fatal(err)
	}
	if p.PromptContext.CursorFile != store || p.PromptContext.CursorFileLabel() != "agents/state/watcher/cursor.json" {
		t.Errorf("prompt_context = %+v", p.PromptContext)
	}
	for name, body := range map[string]string{
		"not listed":       "  cursor: true\n  cursor_file: /srv/notes/agents/state/other/cursor.json\n",
		"not clean":        "  cursor: true\n  cursor_file: /srv/notes/agents/state/watcher/../watcher/cursor.json\n",
		"relative":         "  cursor: true\n  cursor_file: agents/state/watcher/cursor.json\n",
		"without cursor":   "  cursor_file: " + store + "\n",
		"label, no cursor": "  cursor_label: x\n",
	} {
		if _, err := load(body, opts); err == nil {
			t.Errorf("%s: load succeeded, want an error", name)
		}
	}
	// Listed in prompt_state_files, but not this agent's own cursor store: another agent's
	// store, the shared multi-agent state file, a shadow store, another file name.
	listed := pcOptions(t.TempDir())
	for _, f := range []string{
		"/srv/notes/agents/state/other/cursor.json",
		"/srv/notes/agents/state/shared-state.json",
		"/srv/notes/agents/state/watcher-shadow/cursor.json",
		"/srv/notes/agents/state/watcher/other.json",
		"/agents/state/watcher/cursor.json",
	} {
		listed.StateFiles = append(listed.StateFiles, f)
		if _, err := load("  cursor: true\n  cursor_file: "+f+"\n", listed); err == nil {
			t.Errorf("cursor_file %s: load succeeded, want an error", f)
		}
	}
}

// TestLoadRegistry_CursorFileIsNoProfilesStateFile: a cursor_file that is also a state_file --
// the profile's own or any other profile's -- is refused, so one file is never read both as an
// agent's own store and as a shared state file.
func TestLoadRegistry_CursorFileIsNoProfilesStateFile(t *testing.T) {
	const store = "/srv/notes/agents/state/watcher/cursor.json"
	opts := pcOptions(t.TempDir())
	opts.StateFiles = append(opts.StateFiles, store)
	watcher := "id: watcher-v1\nagent_key: watcher\nprompt_context:\n  state_file: /srv/notes/state.json\n  cursor: true\n  cursor_file: " + store + "\n"
	dir := t.TempDir()
	writePCFile(t, filepath.Join(dir, "watcher.yaml"), watcher)
	writePCFile(t, filepath.Join(dir, "peer.yaml"), "id: peer-v1\nagent_key: peer\nprompt_context:\n  state_file: "+store+"\n  own_state: true\n")
	if _, err := LoadRegistry(dir, opts); err == nil || !strings.Contains(err.Error(), "state_file") {
		t.Errorf("a cursor_file that is another profile's state_file loaded (err %v)", err)
	}
	own := t.TempDir()
	writePCFile(t, filepath.Join(own, "watcher.yaml"), "id: watcher-v1\nagent_key: watcher\nprompt_context:\n  state_file: "+store+"\n  cursor: true\n  cursor_file: "+store+"\n")
	if _, err := LoadRegistry(own, opts); err == nil {
		t.Error("a cursor_file that is the profile's own state_file loaded")
	}
}
