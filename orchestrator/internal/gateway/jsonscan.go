// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"unicode/utf8"
)

// The scanner below finds the values of top-level keys in a JSON object without decoding it, so
// a large reply can have its model rewritten without being copied, which bounds the memory a
// reply holds (ADR-0038's security review). It is only ever run on data json.Valid has accepted.

func skipSpace(d []byte, i int) int {
	for i < len(d) && (d[i] == ' ' || d[i] == '\t' || d[i] == '\r' || d[i] == '\n') {
		i++
	}
	return i
}

// scanString returns the index after the string that starts at d[i] == '"', and whether it
// holds an escape.
func scanString(d []byte, i int) (int, bool) {
	esc := false
	for i++; i < len(d); i++ {
		switch d[i] {
		case '\\':
			esc = true
			i++
		case '"':
			return i + 1, esc
		}
	}
	return len(d), esc
}

// scanValue returns the index after the value that starts at d[i].
func scanValue(d []byte, i int) int {
	switch d[i] {
	case '"':
		end, _ := scanString(d, i)
		return end
	case '{', '[':
		depth := 0
		for i < len(d) {
			switch d[i] {
			case '"':
				i, _ = scanString(d, i)
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return i + 1
				}
			}
			i++
		}
		return len(d)
	}
	for i < len(d) && d[i] != ',' && d[i] != '}' && d[i] != ']' && d[i] != ' ' && d[i] != '\t' && d[i] != '\r' && d[i] != '\n' {
		i++
	}
	return i
}

// span is the [start, end) of one top-level value.
type span struct{ start, end int }

// topLevel returns the span of every value whose key, decoded, is one of names (a key spelled
// with escapes, "model", is the key it decodes to, and a key holding invalid UTF-8 is the key
// json.Unmarshal decodes it to, each invalid byte U+FFFD), keyed by name in order of appearance,
// and the index just after the object's '{'. ok is false when data is not a valid JSON object.
func topLevel(data []byte, names ...string) (map[string][]span, int, bool) {
	if !json.Valid(data) {
		return nil, 0, false
	}
	i := skipSpace(data, 0)
	if i >= len(data) || data[i] != '{' {
		return nil, 0, false
	}
	open := i + 1
	out := map[string][]span{}
	i = skipSpace(data, open)
	for i < len(data) && data[i] == '"' {
		kend, esc := scanString(data, i)
		key := string(data[i+1 : kend-1])
		if esc || !utf8.ValidString(key) {
			// decode as json.Unmarshal does: escapes resolved, each invalid byte U+FFFD
			_ = json.Unmarshal(data[i:kend], &key)
		}
		i = skipSpace(data, kend) + 1 // past ':'
		i = skipSpace(data, i)
		vend := scanValue(data, i)
		for _, n := range names {
			if key == n {
				out[n] = append(out[n], span{i, vend})
			}
		}
		i = skipSpace(data, vend)
		if i < len(data) && data[i] == ',' {
			i = skipSpace(data, i+1)
		}
	}
	return out, open, true
}

// last is the value of the last span (what a decoder would keep), or nil.
func last(data []byte, s []span) json.RawMessage {
	if len(s) == 0 {
		return nil
	}
	return data[s[len(s)-1].start:s[len(s)-1].end]
}

// replaceValues returns data as parts with every span replaced by value; with no span, value is
// inserted as key's value right after the object's '{' (open).
func replaceValues(data []byte, spans []span, open int, key string, value []byte) [][]byte {
	if len(spans) == 0 {
		head := append(append(append([]byte{'{'}, mustJSON(key)...), ':'), value...)
		rest := data[open:]
		if r := skipSpace(rest, 0); r < len(rest) && rest[r] != '}' {
			head = append(head, ',')
		}
		return [][]byte{data[:open-1], head, rest}
	}
	parts := make([][]byte, 0, 2*len(spans)+1)
	prev := 0
	for _, s := range spans {
		parts = append(parts, data[prev:s.start], value)
		prev = s.end
	}
	return append(parts, data[prev:])
}
