// SPDX-License-Identifier: Apache-2.0

package prompt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/homelab-next/homelab-next/orchestrator/internal/profile"
	"github.com/homelab-next/homelab-next/orchestrator/internal/safefs"
)

// cursorStoreMaxBytes bounds a cursor store; a larger one is unreadable.
const cursorStoreMaxBytes = 256 << 10

// cursorBlockMaxBytes bounds the cursor a prompt carries; a cut is marked.
const cursorBlockMaxBytes = 12000

// CursorFile is the [prior-cursor] block from an agent's own cursor store: one JSON object a
// cursor tool replaces on the agent's real lane, at the path the cursor template gives the agent
// (profile.DefaultCursorTemplate, the only template a configuration may set for now).
//
// The store is read with safefs, under the template's root: no symbolic link below the root, no
// hard link, no mount crossing, a regular file only (a FIFO is refused without blocking), at most
// 256 KiB, holding exactly one JSON object and nothing after it.
//
//   - fallback is true only when the store does not exist yet (no file, or an empty one): the
//     caller then uses the state file's block (StateCursor), as before the first write.
//   - A stored object, {} included, is the block: dataNotice, then the object as one line of
//     JSON with its keys sorted and every string made one line, at most cursorBlockMaxBytes, in a ```json prior-cursor fence that a
//     stored value cannot close (every backtick is written as the JSON escape for U+0060, the same
//     character inside a JSON string).
//   - A store that cannot be read, or a path that is not agentKey's own store, is a short notice
//     and no cursor, never the state file's block: falling back would hide the fault.
//
// label names the store in the prompt.
func CursorFile(tmpl profile.CursorTemplate, path, label, agentKey string) (block string, fallback bool) {
	root, dir, name, ok := tmpl.StoreAt(path, agentKey)
	if !ok {
		return cursorNotice(agentKey, label), false
	}
	data, err := safefs.FS{Root: root, Label: "cursor store"}.ReadFile(dir+"/"+name, cursorStoreMaxBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return "", true
	}
	if err != nil {
		return cursorNotice(agentKey, label), false
	}
	if len(data) == 0 {
		return "", true
	}
	if err := checkObject(data); err != nil {
		return cursorNotice(agentKey, label), false
	}
	compact, err := compactJSON(data) // keys sorted: the same text for the same store
	if err != nil {
		return cursorNotice(agentKey, label), false
	}
	body := strings.ReplaceAll(compact, "`", "\\u0060")
	if b, truncated := cut(body, cursorBlockMaxBytes); truncated {
		body = b + " ...[cut]"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[prior-cursor] The %s agent's own cursor as its last real-lane run saved it (%s). Only a real-lane run updates it, through its cursor tool; without that tool you cannot, so state your new cursor values in your output instead.\n", agentKey, oneLine(label))
	b.WriteString(dataNotice + "\n")
	fmt.Fprintf(&b, "```json prior-cursor\n%s\n```\n", body)
	b.WriteString("Trend this run against that cursor: report the change, not the whole state.\n")
	return b.String(), false
}

// checkObject reports whether data is exactly one JSON object with nothing after it.
func checkObject(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return errors.New("not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the JSON object")
	}
	return nil
}

// cursorNotice is the [prior-cursor] block for a store that cannot be read.
func cursorNotice(agentKey, label string) string {
	return fmt.Sprintf("[prior-cursor] The %s agent's cursor store (%s) could not be read: it is not this agent's own store, not a plain file, larger than 256 KiB, or not exactly one JSON object. No prior cursor is given this run: treat it as a first run, and report the unreadable store in your output.\n", agentKey, oneLine(label))
}
