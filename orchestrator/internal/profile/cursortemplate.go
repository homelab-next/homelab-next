// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// DefaultCursorTemplate is where an agent's own cursor store lives: {root} is any clean
// absolute directory (the store's root), {agent_key} the profile's own agent key. The
// controller config's cursor_file_template accepts only this template for now: the cursor tool
// that writes the store (an MCP module, not this repository's code yet) takes no such setting,
// and any other layout would inject a cursor that tool never touches.
const DefaultCursorTemplate = "{root}/agents/state/{agent_key}/cursor.json"

// CursorTemplate is a parsed cursor_file_template: the one path shape a
// profile's prompt_context.cursor_file may take, per agent. The zero value is
// DefaultCursorTemplate.
type CursorTemplate struct {
	dir  string // relative directory under {root}, with {agent_key}
	name string // the store's file name
}

const (
	rootPlaceholder  = "{root}"
	agentPlaceholder = "{agent_key}"
)

// cursorAgentKey is the canonical agent key a cursor store may belong to: the rule
// the cursor tool applies to the agent it serves.
var cursorAgentKey = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)

// ParseCursorTemplate parses a cursor_file_template. "" is
// DefaultCursorTemplate. The template must be "{root}/<dir>/<file>": <dir> a
// clean relative path with {agent_key} as exactly one whole component (so each
// agent's store is its own directory), <file> a plain file name, and no other
// placeholder anywhere.
func ParseCursorTemplate(t string) (CursorTemplate, error) {
	if t == "" {
		t = DefaultCursorTemplate
	}
	rest, ok := strings.CutPrefix(t, rootPlaceholder+"/")
	if !ok {
		return CursorTemplate{}, fmt.Errorf("cursor_file_template %q must start with %s/", t, rootPlaceholder)
	}
	dir, name := filepath.Split(rest)
	dir = strings.TrimSuffix(dir, "/")
	switch {
	case dir == "" || name == "":
		return CursorTemplate{}, fmt.Errorf("cursor_file_template %q needs a directory and a file name under %s", t, rootPlaceholder)
	case strings.ContainsAny(name, "{}") || name == "." || name == "..":
		return CursorTemplate{}, fmt.Errorf("cursor_file_template %q: the file name must be plain", t)
	case filepath.Clean(dir) != dir || !filepath.IsLocal(dir) || strings.Contains(dir, `\`):
		return CursorTemplate{}, fmt.Errorf("cursor_file_template %q: the directory must be a clean relative path", t)
	}
	n := 0
	for _, part := range strings.Split(dir, "/") {
		if part == agentPlaceholder {
			n++
		} else if strings.ContainsAny(part, "{}") {
			return CursorTemplate{}, fmt.Errorf("cursor_file_template %q: %q is not a placeholder it knows (%s, %s)", t, part, rootPlaceholder, agentPlaceholder)
		}
	}
	if n != 1 {
		return CursorTemplate{}, fmt.Errorf("cursor_file_template %q must name %s as exactly one whole directory component", t, agentPlaceholder)
	}
	return CursorTemplate{dir: dir, name: name}, nil
}

func (t CursorTemplate) parts() (dir, name string) {
	if t.dir == "" {
		t, _ = ParseCursorTemplate(DefaultCursorTemplate)
	}
	return t.dir, t.name
}

// String is the template text.
func (t CursorTemplate) String() string {
	dir, name := t.parts()
	return rootPlaceholder + "/" + dir + "/" + name
}

// StoreAt reports whether path is agentKey's own cursor store under this
// template, and returns its pieces: root (a clean absolute directory, never
// "/"), dir (relative to root, agent key substituted) and the file name.
// Anything else -- another agent's store, a shadow store, a shared state
// file, an unclean spelling -- is not that agent's store.
func (t CursorTemplate) StoreAt(path, agentKey string) (root, dir, name string, ok bool) {
	if !cursorAgentKey.MatchString(agentKey) || len(agentKey) > 80 || strings.HasSuffix(agentKey, "-shadow") {
		return "", "", "", false
	}
	tdir, name := t.parts()
	dir = strings.ReplaceAll(tdir, agentPlaceholder, agentKey)
	root, ok = strings.CutSuffix(path, "/"+dir+"/"+name)
	if !ok || root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Join(root, dir, name) != path {
		return "", "", "", false
	}
	return root, dir, name, true
}
