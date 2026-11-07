// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/homelab-next/homelab-next/orchestrator/internal/grants"
	"github.com/homelab-next/homelab-next/orchestrator/internal/safefs"
)

// PromptContext is the per-profile data the controller folds into a dispatch
// prompt beyond the task text and the register context. Every block below is
// off unless the profile turns it on.
//
// A profile can only point at things the controller's operator listed: a
// facts command by its name in the controller's facts_commands catalog, a
// state file that is in prompt_state_files, and text files inside prompt_dir
// (LoadOptions). Anything else fails the load, so a profile can neither run a
// program nor read a file into a prompt that the controller config did not
// name. The text files are read once, at load: a missing file fails the load,
// never a dispatch.
type PromptContext struct {
	// StateFile is a JSON state file with a top-level "agents" map keyed by
	// agent key. Read-only to the controller. Needed by KnownIncidentsKey,
	// OwnState and Cursor. It must be one of LoadOptions.StateFiles.
	StateFile string `yaml:"state_file"`
	// StateLabel is how prompt text names the state file. Empty = the file's
	// base name.
	StateLabel string `yaml:"state_label"`
	// KnownIncidentsKey selects whose open_incidents block is injected as
	// [known-incidents]. Empty = off.
	KnownIncidentsKey string `yaml:"known_incidents_key"`
	// OwnState injects this agent's own block, compacted, as [own-state].
	OwnState bool `yaml:"own_state"`
	// Cursor injects this agent's own string fields as [prior-cursor].
	Cursor bool `yaml:"cursor"`
	// CursorFile, with Cursor, is the agent's own cursor store: exactly the
	// controller's cursor_file_template for this profile's own agent_key
	// (LoadOptions.CursorTemplate; by default
	// <root>/agents/state/<agent_key>/cursor.json), the file the agent's cursor
	// tool replaces on the real lane. The prompt builder reads it as that tool
	// does (no symlinks, a regular file only, bounded, exactly one JSON object):
	// a stored object, {} included, is the [prior-cursor] block; only a store
	// that does not exist yet falls back to the StateFile block; a store that
	// cannot be read gets a notice block and no cursor. It must be one of
	// LoadOptions.StateFiles, like StateFile, and no profile's state_file.
	// Empty = StateFile only.
	CursorFile string `yaml:"cursor_file"`
	// CursorLabel is how prompt text names CursorFile. Empty = the file's
	// base name.
	CursorLabel string `yaml:"cursor_label"`
	// cursorTemplate is the template CursorFile was validated against at
	// load (CursorTemplate()).
	cursorTemplate CursorTemplate
	// Facts names an entry of the controller's facts_commands catalog
	// (LoadOptions.FactsCommands). The command runs at dispatch; its trimmed
	// stdout is injected as [deterministic-facts]. Empty = off. A failure,
	// timeout or empty output only drops the block.
	Facts string `yaml:"facts"`
	// FactsTimeoutS bounds the facts command, in seconds: 0 = 60s, else 1..600
	// (maxFactsTimeoutS; a larger value fails the load).
	FactsTimeoutS int `yaml:"facts_timeout_s"`
	// FactsPreambleFile replaces the generic first line of the facts block.
	// Like the appendix files, a path relative to prompt_dir.
	FactsPreambleFile string `yaml:"facts_preamble_file"`
	// AppendixFiles are appended, in order, to every prompt of this profile;
	// RealAppendixFiles / ShadowAppendixFiles only to that lane's prompts,
	// after AppendixFiles. Paths are relative to prompt_dir.
	AppendixFiles       []string `yaml:"appendix_files"`
	RealAppendixFiles   []string `yaml:"real_appendix_files"`
	ShadowAppendixFiles []string `yaml:"shadow_appendix_files"`

	// Resolved at load (never from YAML).
	FactsCommand   FactsCommand `yaml:"-"` // the catalog entry Facts names
	FactsPreamble  string       `yaml:"-"`
	Appendix       []string     `yaml:"-"`
	RealAppendix   []string     `yaml:"-"`
	ShadowAppendix []string     `yaml:"-"`
}

// FactsCommand is one entry of the controller's facts_commands catalog.
//
// Argv runs without a shell. Argv[0] is an absolute path, or a bare program
// name (no "/") looked up on the controller's own PATH; a relative path with a
// "/" is refused because it would depend on the controller's working
// directory.
//
// The process gets a scrubbed environment: only BaseFactsEnv (PATH, HOME,
// LANG, LC_*, TZ) plus the variables named in Env, each with the value it has
// in the controller's environment (a name the controller does not have is
// left unset). Nothing else of the controller's environment -- API keys,
// tokens -- reaches the command, so its output cannot carry them into a
// prompt unless the operator listed them here.
type FactsCommand struct {
	Argv []string `yaml:"argv"`
	Env  []string `yaml:"env"`
}

// factsEnvNameRe is the shape of a name in FactsCommand.Env: no wildcard, no space, no "=".
var factsEnvNameRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// maxFactsTimeoutS caps facts_timeout_s: a facts command runs before every dispatch of the profile,
// so ten minutes is already far beyond any real one (and keeps the value a valid time.Duration).
const maxFactsTimeoutS = 600

// BaseFactsEnv are the variables every facts command inherits from the
// controller; a trailing "*" is a prefix match.
var BaseFactsEnv = []string{"PATH", "HOME", "LANG", "LC_*", "TZ"}

// Validate reports a malformed catalog entry.
func (f FactsCommand) Validate() error {
	if len(f.Argv) == 0 || f.Argv[0] == "" {
		return fmt.Errorf("argv is empty")
	}
	prog := f.Argv[0]
	if prog == "." || prog == ".." || (!filepath.IsAbs(prog) && strings.ContainsRune(prog, '/')) {
		return fmt.Errorf("argv[0] %q must be an absolute path or a bare program name", prog)
	}
	for _, a := range f.Argv {
		if strings.ContainsRune(a, 0) {
			return fmt.Errorf("argv holds a NUL byte")
		}
	}
	for _, name := range f.Env {
		if !factsEnvNameRe.MatchString(name) {
			return fmt.Errorf("env name %q is not a variable name (want %s)", name, factsEnvNameRe)
		}
		if grants.DeniedEnv(name) {
			return fmt.Errorf("env name %s changes what code runs or how (the grants deny list) and may not be passed to a facts command", name)
		}
	}
	return nil
}

// Environ builds the facts process environment from the controller's own
// (environ, os.Environ's form): BaseFactsEnv plus f.Env, nothing else.
func (f FactsCommand) Environ(environ []string) []string {
	keep := func(name string) bool {
		for _, b := range BaseFactsEnv {
			if p, ok := strings.CutSuffix(b, "*"); ok {
				if strings.HasPrefix(name, p) {
					return true
				}
			} else if name == b {
				return true
			}
		}
		for _, e := range f.Env {
			if name == e {
				return true
			}
		}
		return false
	}
	out := []string{}
	for _, kv := range environ {
		name, _, ok := strings.Cut(kv, "=")
		if ok && name != "" && keep(name) {
			out = append(out, kv)
		}
	}
	return out
}

func (f FactsCommand) clone() FactsCommand {
	return FactsCommand{Argv: append([]string(nil), f.Argv...), Env: append([]string(nil), f.Env...)}
}

// maxPromptFileBytes bounds one appendix / preamble file.
const maxPromptFileBytes = 1 << 20

// promptEnv is LoadOptions' prompt-context half, validated once per load.
type promptEnv struct {
	promptDir  string
	stateFiles map[string]bool
	facts      map[string]FactsCommand
	cursor     CursorTemplate
}

func newPromptEnv(opts LoadOptions) (promptEnv, error) {
	env := promptEnv{promptDir: opts.PromptDir, stateFiles: map[string]bool{}, facts: map[string]FactsCommand{}, cursor: opts.CursorTemplate}
	if env.promptDir != "" {
		fi, err := os.Stat(env.promptDir)
		if err != nil {
			return env, fmt.Errorf("prompt_dir: %w", err)
		}
		if !fi.IsDir() {
			return env, fmt.Errorf("prompt_dir %s is not a directory", env.promptDir)
		}
	}
	for _, s := range opts.StateFiles {
		if !filepath.IsAbs(s) {
			return env, fmt.Errorf("prompt_state_files: %q is not an absolute path", s)
		}
		env.stateFiles[filepath.Clean(s)] = true
	}
	names := make([]string, 0, len(opts.FactsCommands))
	for name := range opts.FactsCommands {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fc := opts.FactsCommands[name]
		if strings.TrimSpace(name) == "" {
			return env, fmt.Errorf("facts_commands: empty name")
		}
		if err := fc.Validate(); err != nil {
			return env, fmt.Errorf("facts_commands %s: %w", name, err)
		}
		env.facts[name] = fc.clone()
	}
	return env, nil
}

// readPromptFile reads name from inside prompt_dir. Absolute paths, any ".."
// component, symlinks (even ones that stay inside), hard links and mount
// crossings are refused (safefs).
func (e promptEnv) readPromptFile(name string) ([]byte, error) {
	if e.promptDir == "" {
		return nil, fmt.Errorf("%q: the controller has no prompt_dir configured", name)
	}
	if name == "" || filepath.IsAbs(name) || !filepath.IsLocal(name) {
		return nil, fmt.Errorf("%q must be a relative path inside prompt_dir", name)
	}
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if part == ".." {
			return nil, fmt.Errorf("%q must not contain \"..\"", name)
		}
	}
	return safefs.FS{Root: e.promptDir, Label: "prompt_dir"}.ReadFile(name, maxPromptFileBytes)
}

// Label is StateLabel, or the state file's base name.
func (c PromptContext) Label() string {
	if c.StateLabel != "" {
		return c.StateLabel
	}
	return filepath.Base(c.StateFile)
}

// CursorTemplate is the cursor_file_template CursorFile was validated against
// (DefaultCursorTemplate for a profile not loaded through LoadRegistry).
func (c PromptContext) CursorTemplate() CursorTemplate { return c.cursorTemplate }

// CursorFileLabel is how prompt text names CursorFile.
func (c PromptContext) CursorFileLabel() string {
	if c.CursorLabel != "" {
		return c.CursorLabel
	}
	return filepath.Base(c.CursorFile)
}

// LaneAppendix is the appendix texts for one lane, in prompt order.
func (c PromptContext) LaneAppendix(shadow bool) []string {
	out := append([]string(nil), c.Appendix...)
	if shadow {
		return append(out, c.ShadowAppendix...)
	}
	return append(out, c.RealAppendix...)
}

// resolve validates the block against env and reads the referenced files. It
// returns the bytes of everything it resolved (each file read, and the facts
// catalog entry), in a fixed order, so the profile revision changes when one
// of them does.
func (c *PromptContext) resolve(env promptEnv, agentKey string) ([]byte, error) {
	if (c.KnownIncidentsKey != "" || c.OwnState || c.Cursor) && c.StateFile == "" {
		return nil, fmt.Errorf("prompt_context: known_incidents_key, own_state and cursor need state_file")
	}
	// Which block wins when both are asked for is not guessed: the
	// combination is refused.
	if c.OwnState && (c.Facts != "" || c.KnownIncidentsKey != "") {
		return nil, fmt.Errorf("prompt_context: own_state (or inject_own_state) cannot be combined with facts or known_incidents_key")
	}
	if c.FactsTimeoutS < 0 || c.FactsTimeoutS > maxFactsTimeoutS {
		return nil, fmt.Errorf("prompt_context: facts_timeout_s must be 0 (the 60s default) or 1..%d, got %d", maxFactsTimeoutS, c.FactsTimeoutS)
	}
	if (c.CursorFile != "" || c.CursorLabel != "") && !c.Cursor {
		return nil, fmt.Errorf("prompt_context: cursor_file and cursor_label need cursor: true")
	}
	if c.CursorFile != "" {
		if !filepath.IsAbs(c.CursorFile) || filepath.Clean(c.CursorFile) != c.CursorFile || !env.stateFiles[c.CursorFile] {
			return nil, fmt.Errorf("prompt_context: cursor_file %q is not in the controller's prompt_state_files", c.CursorFile)
		}
		// Only the agent's own store: never another agent's, nor a shared state file that would
		// put every agent's block into this agent's prompt.
		if _, _, _, ok := env.cursor.StoreAt(c.CursorFile, agentKey); !ok {
			return nil, fmt.Errorf("prompt_context: cursor_file %q is not this agent's cursor store (%s)", c.CursorFile, strings.ReplaceAll(env.cursor.String(), agentPlaceholder, agentKey))
		}
		c.cursorTemplate = env.cursor
		if c.CursorFile == c.StateFile {
			return nil, fmt.Errorf("prompt_context: cursor_file %q is also the state_file", c.CursorFile)
		}
	}
	var read []byte
	if c.StateFile != "" {
		// Exact match on a clean path: "/a/x/../b" is not accepted as "/a/b",
		// because the kernel resolves ".." after any symlink at x.
		if !filepath.IsAbs(c.StateFile) || filepath.Clean(c.StateFile) != c.StateFile || !env.stateFiles[c.StateFile] {
			return nil, fmt.Errorf("prompt_context: state_file %q is not in the controller's prompt_state_files", c.StateFile)
		}
	}
	if c.Facts != "" {
		fc, ok := env.facts[c.Facts]
		if !ok {
			return nil, fmt.Errorf("prompt_context: facts %q is not in the controller's facts_commands", c.Facts)
		}
		c.FactsCommand = fc.clone()
		read = append(read, 0)
		read = append(read, "facts:"+strings.Join(fc.Argv, "\x00")+"\x01"+strings.Join(fc.Env, "\x00")...)
	} else if c.FactsPreambleFile != "" || c.FactsTimeoutS != 0 {
		return nil, fmt.Errorf("prompt_context: facts_preamble_file and facts_timeout_s need facts")
	}
	load := func(name string) (string, error) {
		data, err := env.readPromptFile(name)
		if err != nil {
			return "", fmt.Errorf("prompt_context: %w", err)
		}
		read = append(read, 0)
		read = append(read, data...)
		return strings.TrimSuffix(string(data), "\n"), nil
	}
	loadAll := func(names []string) ([]string, error) {
		var out []string
		for _, n := range names {
			text, err := load(n)
			if err != nil {
				return nil, err
			}
			out = append(out, text)
		}
		return out, nil
	}
	var err error
	if c.FactsPreambleFile != "" {
		if c.FactsPreamble, err = load(c.FactsPreambleFile); err != nil {
			return nil, err
		}
	}
	if c.Appendix, err = loadAll(c.AppendixFiles); err != nil {
		return nil, err
	}
	if c.RealAppendix, err = loadAll(c.RealAppendixFiles); err != nil {
		return nil, err
	}
	if c.ShadowAppendix, err = loadAll(c.ShadowAppendixFiles); err != nil {
		return nil, err
	}
	return read, nil
}

func (c PromptContext) clone() PromptContext {
	cp := c
	cp.FactsCommand = c.FactsCommand.clone()
	cp.AppendixFiles = append([]string(nil), c.AppendixFiles...)
	cp.RealAppendixFiles = append([]string(nil), c.RealAppendixFiles...)
	cp.ShadowAppendixFiles = append([]string(nil), c.ShadowAppendixFiles...)
	cp.Appendix = append([]string(nil), c.Appendix...)
	cp.RealAppendix = append([]string(nil), c.RealAppendix...)
	cp.ShadowAppendix = append([]string(nil), c.ShadowAppendix...)
	return cp
}
