// SPDX-License-Identifier: Apache-2.0

package prompt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"sort"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

// A state file is a JSON object whose "agents" member maps an agent key to that agent's own block,
// which only that agent's real-lane runs write. The controller reads it and never writes it. The
// blocks are prose a model wrote: every block built from them opens with dataNotice, every key and
// value is one line, and every block is bounded in total as well as per value, whatever the file
// holds (a file of up to maxStateBytes is read).

const (
	// maxStateBytes bounds a state file; a larger one is not read.
	maxStateBytes = 4 << 20
	// ownStateMaxBytes bounds the [own-state] block's JSON; a cut is marked.
	ownStateMaxBytes = 6000
	// stateBlockMaxBytes bounds the entries of a [known-incidents] or state [prior-cursor] block
	// together; the entries past it are counted, not shown.
	stateBlockMaxBytes = 12000
	// stateEntriesMax bounds how many entries such a block shows.
	stateEntriesMax = 64
	// stateFieldMaxBytes bounds one value; a cut is marked.
	stateFieldMaxBytes = 6000
	// stateNameMaxBytes bounds a key, an incident id, last_run and last_status.
	stateNameMaxBytes = 128
)

// readState returns the state file's bytes, or nil when it cannot be read: missing, a symbolic
// link (the configured path's links were resolved at load, profile.ResolvedStateFile, so a link
// at the file now is one swapped in since), not a regular file (a FIFO is opened without blocking
// and refused), larger than maxStateBytes.
//
// A missing file is a state not written yet and is silent; every other refusal is logged, so a
// block that went missing for a reason can be found.
func readState(path string) []byte {
	if path == "" {
		return nil
	}
	refuse := func(why string) []byte {
		log.Printf("state file %s: %s (its blocks are left out)", path, why)
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if errors.Is(err, syscall.ELOOP) {
		return refuse("a symbolic link (links are resolved once, when the profile loads)")
	}
	if err != nil {
		return refuse(err.Error())
	}
	defer f.Close()
	fi, err := f.Stat()
	switch {
	case err != nil:
		return refuse(err.Error())
	case !fi.Mode().IsRegular():
		return refuse("not a regular file")
	case fi.Size() > maxStateBytes:
		return refuse(fmt.Sprintf("%d bytes, over the %d-byte bound", fi.Size(), maxStateBytes))
	}
	data, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil {
		return refuse(err.Error())
	}
	if len(data) > maxStateBytes {
		return refuse(fmt.Sprintf("grew past the %d-byte bound while it was read", maxStateBytes))
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

// oneLine makes model-written text one line of data: every control character (C0, DEL, C1 and
// NEL among them), format character and line or paragraph separator becomes a space, so a value
// cannot pose as a line of the prompt's own; invalid UTF-8 becomes U+FFFD.
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

// name is a key, an id or a short field as one bounded line.
func name(s string) string {
	v, truncated := cut(oneLine(s), stateNameMaxBytes)
	if truncated {
		v += "..."
	}
	return v
}

// value is a value as one bounded line, a cut marked.
func value(s string) string {
	v, truncated := cut(oneLine(s), stateFieldMaxBytes)
	if truncated {
		v += " ...[cut]"
	}
	return v
}

// entries writes lines while they fit stateEntriesMax and stateBlockMaxBytes together, then one
// line counting what was left out.
func entries(b *strings.Builder, lines []string) {
	used := 0
	for i, l := range lines {
		if i == stateEntriesMax || used+len(l) > stateBlockMaxBytes {
			fmt.Fprintf(b, "[%d more entries not shown]\n", len(lines)-i)
			return
		}
		b.WriteString(l)
		used += len(l)
	}
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
	lines := make([]string, len(ids))
	for i, id := range ids {
		lines[i] = "- " + name(id) + ": " + value(blk.OpenIncidents[id]) + "\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[known-incidents] The %s agent tracks %d incident(s) as of its last real-lane run.\n", agentKey, len(ids))
	b.WriteString(dataNotice + "\n")
	fmt.Fprintf(&b, "Last run: %s; status: %s\n", name(blk.LastRun), name(blk.LastStatus))
	entries(&b, lines)
	b.WriteString("If your own pass confirms one of these again, refer to it by its id and say only whether it changed; report as new only an issue that is not listed.\n")
	return b.String()
}

// sanitize returns v (decoded JSON) with every string, keys included, made one line.
func sanitize(v any) any {
	switch x := v.(type) {
	case string:
		return oneLine(x)
	case []any:
		for i := range x {
			x[i] = sanitize(x[i])
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, c := range x {
			out[oneLine(k)] = sanitize(c)
		}
		return out
	}
	return v
}

// compactJSON decodes data (numbers as written), makes every string in it one line and encodes it
// again with sorted keys: one line of JSON with no character in it that could break a line, raw
// or escaped.
func compactJSON(data []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(sanitize(v)); err != nil {
		return "", err
	}
	return strings.TrimSuffix(out.String(), "\n"), nil
}

// OwnState is the [own-state] block: agentKey's own block, whatever its shape, as one line of
// JSON (every string made one line, keys sorted), at most ownStateMaxBytes (a cut is marked).
// label names the state file. "" when the file cannot be read or the block is missing, null or
// empty.
func OwnState(stateFile, label, agentKey string) string {
	raw := agentBlock(stateFile, agentKey)
	if raw == nil {
		return ""
	}
	body, err := compactJSON(raw)
	if err != nil || body == "null" || body == "{}" || body == `""` || body == "[]" {
		return ""
	}
	body, truncated := cut(body, ownStateMaxBytes)
	var b strings.Builder
	fmt.Fprintf(&b, "[own-state] %s's block for %s, as the agent's last real-lane run left it. It is read-only: only a real-lane run writes it, so do not claim to have updated it.\n", name(label), agentKey)
	b.WriteString(dataNotice + "\n")
	b.WriteString(body + "\n")
	if truncated {
		fmt.Fprintf(&b, "[own-state cut at %d bytes]\n", ownStateMaxBytes)
	}
	b.WriteString("Use it as your cursor: report only what is new relative to it, refer to items it already tracks by its wording, and state in your output what the next cursor should be.\n")
	return b.String()
}

// StateCursor is the [prior-cursor] block from the state file: the string fields of agentKey's
// block, sorted by key, each one bounded line; fields of any other type are left out. label names
// the state file. "" when the file cannot be read or the block has no string field.
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
	var lines []string
	for _, k := range keys {
		var s string
		if json.Unmarshal(blk[k], &s) != nil {
			continue
		}
		lines = append(lines, "- "+name(k)+": "+value(s)+"\n")
	}
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[prior-cursor] The %s agent's own cursor from its last real-lane run (%s). It is read-only: do not claim to have updated it; state your new cursor values in your output instead.\n", agentKey, name(label))
	b.WriteString(dataNotice + "\n")
	entries(&b, lines)
	b.WriteString("Trend this run against that cursor: report the change, not the whole state.\n")
	return b.String()
}
