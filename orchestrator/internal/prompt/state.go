// SPDX-License-Identifier: Apache-2.0

package prompt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

// A state file is a JSON object whose "agents" member maps an agent key to that agent's own block,
// which only that agent's real-lane runs write. The controller reads it and never writes it. The
// blocks are prose a model wrote: every block built from them opens with dataNotice, and every
// value is one line.

// maxStateBytes bounds a state file; a larger one is not read.
const maxStateBytes = 4 << 20

// ownStateMaxBytes bounds the [own-state] block's JSON; a cut is marked.
const ownStateMaxBytes = 6000

// stateFieldMaxBytes bounds each field of the state file's [prior-cursor] block; a cut is marked.
const stateFieldMaxBytes = 6000

// readState returns the state file's bytes, or nil when it cannot be read: missing, not a regular
// file (a FIFO is opened without blocking and refused), larger than maxStateBytes. The path is
// one the controller's configuration lists (prompt_state_files), so a symbolic link to it is the
// operator's to make and is followed.
func readState(path string) []byte {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxStateBytes {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil || len(data) > maxStateBytes {
		return nil
	}
	return data
}

// agentBlock returns agentKey's raw block from the state file, or nil.
func agentBlock(path, agentKey string) json.RawMessage {
	if agentKey == "" {
		return nil
	}
	data := readState(path)
	if data == nil {
		return nil
	}
	var st struct {
		Agents map[string]json.RawMessage `json:"agents"`
	}
	if json.Unmarshal(data, &st) != nil {
		return nil
	}
	return st.Agents[agentKey]
}

// oneLine makes model-written text one line of data: every control, format and line-break
// character becomes a space, so a value cannot pose as a line of the prompt's own.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
}

// cut shortens s to at most max bytes on a rune boundary, reporting whether it did.
func cut(s string, max int) (string, bool) {
	if len(s) <= max {
		return s, false
	}
	n := max
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n], true
}

// KnownIncidents is the [known-incidents] block: the incidents agentKey's block tracks
// (open_incidents, a map of incident id to its status), sorted by id, so a run refers to a
// tracked incident by its id instead of reporting it as new. "" when the file cannot be read or
// the block tracks none.
func KnownIncidents(stateFile, agentKey string) string {
	raw := agentBlock(stateFile, agentKey)
	if raw == nil {
		return ""
	}
	var blk struct {
		LastRun       string            `json:"last_run"`
		LastStatus    string            `json:"last_status"`
		OpenIncidents map[string]string `json:"open_incidents"`
	}
	if json.Unmarshal(raw, &blk) != nil || len(blk.OpenIncidents) == 0 {
		return ""
	}
	ids := make([]string, 0, len(blk.OpenIncidents))
	for id := range blk.OpenIncidents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b strings.Builder
	fmt.Fprintf(&b, "[known-incidents] The %s agent tracks %d incident(s) as of its last real-lane run (%s, status %s).\n",
		agentKey, len(ids), oneLine(blk.LastRun), oneLine(blk.LastStatus))
	b.WriteString(dataNotice + "\n")
	for _, id := range ids {
		v, _ := cut(oneLine(blk.OpenIncidents[id]), stateFieldMaxBytes)
		fmt.Fprintf(&b, "- %s: %s\n", oneLine(id), v)
	}
	b.WriteString("If your own pass confirms one of these again, refer to it by its id and say only whether it changed; report as new only an issue that is not listed.\n")
	return b.String()
}

// OwnState is the [own-state] block: agentKey's own block, whatever its shape, as compact JSON
// (one line), at most ownStateMaxBytes (a cut is marked). label names the state file. "" when
// the file cannot be read or the block is missing, null or empty.
func OwnState(stateFile, label, agentKey string) string {
	raw := agentBlock(stateFile, agentKey)
	if raw == nil {
		return ""
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return ""
	}
	body := compact.String()
	if body == "null" || body == "{}" || body == `""` || body == "[]" {
		return ""
	}
	body, truncated := cut(body, ownStateMaxBytes)
	var b strings.Builder
	fmt.Fprintf(&b, "[own-state] %s's block for %s, as the agent's last real-lane run left it. It is read-only: only a real-lane run writes it, so do not claim to have updated it.\n", oneLine(label), agentKey)
	b.WriteString(dataNotice + "\n")
	b.WriteString(body + "\n")
	if truncated {
		fmt.Fprintf(&b, "[own-state cut at %d bytes]\n", ownStateMaxBytes)
	}
	b.WriteString("Use it as your cursor: report only what is new relative to it, refer to items it already tracks by its wording, and state in your output what the next cursor should be.\n")
	return b.String()
}

// StateCursor is the [prior-cursor] block from the state file: every string field of agentKey's
// block, sorted by key, each one line of at most stateFieldMaxBytes (a cut is marked); fields of
// any other type are left out. label names the state file. "" when the file cannot be read or
// the block has no string field.
func StateCursor(stateFile, label, agentKey string) string {
	raw := agentBlock(stateFile, agentKey)
	if raw == nil {
		return ""
	}
	var blk map[string]json.RawMessage
	if json.Unmarshal(raw, &blk) != nil || len(blk) == 0 {
		return ""
	}
	keys := make([]string, 0, len(blk))
	for k := range blk {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var fields strings.Builder
	for _, k := range keys {
		var s string
		if json.Unmarshal(blk[k], &s) != nil {
			continue
		}
		v, truncated := cut(oneLine(s), stateFieldMaxBytes)
		if truncated {
			v += " ...[cut]"
		}
		fmt.Fprintf(&fields, "- %s: %s\n", oneLine(k), v)
	}
	if fields.Len() == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[prior-cursor] The %s agent's own cursor from its last real-lane run (%s). It is read-only: do not claim to have updated it; state your new cursor values in your output instead.\n", agentKey, oneLine(label))
	b.WriteString(dataNotice + "\n")
	b.WriteString(fields.String())
	b.WriteString("Trend this run against that cursor: report the change, not the whole state.\n")
	return b.String()
}
