// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/homelab-next/homelab-next/orchestrator/internal/fuzzseed"
)

// The fuzz targets of the gateway's hand-written readers (ADR-0048 decision 1). Each property is
// a function of the reference it compares with; the _test.go holds a deliberately wrong reference
// beside each, and TestFuzz*PropertyCanFail proves on the seed corpus that the property, checked
// against the wrong one, fails.

// --- FuzzJSONScan ---

// member is one top-level key, decoded, and its value's bytes.
type member struct {
	key string
	raw string
}

// decoderMembers is the reference: every top-level member json.Decoder finds, in order,
// duplicates included.
func decoderMembers(data []byte) ([]member, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	var out []member
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, false
		}
		out = append(out, member{tok.(string), string(raw)})
	}
	return out, true
}

// keptRef is what a decoder keeps of a key that appears more than once.
type keptRef func(data []byte) (map[string]json.RawMessage, bool)

// unmarshalKept is the reference: json.Unmarshal into a map, which keeps the last.
func unmarshalKept(data []byte) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

// firstKept is the wrong reference: the first of each key.
func firstKept(data []byte) (map[string]json.RawMessage, bool) {
	ms, ok := decoderMembers(data)
	if !ok {
		return nil, false
	}
	m := map[string]json.RawMessage{}
	for _, x := range ms {
		if _, seen := m[x.key]; !seen {
			m[x.key] = json.RawMessage(x.raw)
		}
	}
	return m, true
}

// absentKey is a name topLevel is also asked for, to show it finds no key the decoder does not;
// when the input does hold it, it is an ordinary key and the probe proves nothing.
const absentKey = "\x00absent"

// jsonScanProperty: on input json.Valid accepts, topLevel finds an object exactly when the
// decoder does, finds for each key the spans of every occurrence in order (decoded keys, so a key
// spelled with escapes is the key it decodes to), each span is the value's own bytes, and last
// of them is the value the decoder keeps (topLevel's doc comment: last is "what a decoder would
// keep"). Off json.Valid it reports no object.
func jsonScanProperty(kept keptRef, data []byte) error {
	if !json.Valid(data) {
		if _, _, ok := topLevel(data, "model"); ok {
			return fmt.Errorf("topLevel accepts %q, which json.Valid refuses", data)
		}
		return nil
	}
	members, isObject := decoderMembers(data)
	m, _ := kept(data)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	names := keys
	if _, real := m[absentKey]; !real {
		names = append(slices.Clone(keys), absentKey)
	}
	spans, open, ok := topLevel(data, names...)
	if ok != isObject {
		return fmt.Errorf("topLevel(%q) ok = %v, the decoder finds an object: %v", data, ok, isObject)
	}
	if !ok {
		return nil
	}
	if open < 1 || data[open-1] != '{' {
		return fmt.Errorf("topLevel(%q): open %d is not just after the object's '{'", data, open)
	}
	if _, real := m[absentKey]; (!real && len(spans[absentKey]) != 0) || len(spans) > len(keys) {
		return fmt.Errorf("topLevel(%q) finds a key the decoder does not: %v", data, spans)
	}
	for _, k := range keys {
		var want []string
		for _, x := range members {
			if x.key == k {
				want = append(want, x.raw)
			}
		}
		var got []string
		for _, s := range spans[k] {
			got = append(got, string(data[s.start:s.end]))
		}
		if !reflect.DeepEqual(got, want) {
			return fmt.Errorf("topLevel(%q) finds %q for key %q, the decoder %q", data, got, k, want)
		}
		if l := string(last(data, spans[k])); l != string(m[k]) {
			return fmt.Errorf("last of key %q in %q is %q, the decoder keeps %q", k, data, l, m[k])
		}
	}
	return nil
}

var jsonScanSeeds = [][]any{
	{[]byte(`{"model":"m","usage":{"prompt_tokens":1},"choices":[{"message":{"content":"x"}}]}`)},
	{[]byte(` { "a" : [1, {"b": "}"}] , "c":"\"" , "d" : -1.5e3 , "e":true,"f":null } `)},
	{[]byte(`{"model":"escaped key","x\"y":1}`)},
	{[]byte(`{}`)},
	{[]byte(`[1,2]`)},
	{[]byte(`null`)},
	{[]byte(`{"a":1,}`)},
}

func FuzzJSONScan(f *testing.F) {
	for _, s := range jsonScanSeeds {
		f.Add(s[0].([]byte))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := jsonScanProperty(unmarshalKept, data); err != nil {
			t.Fatal(err)
		}
	})
}

func jsonScanWith(k keptRef) func([]any) error {
	return func(a []any) error { return jsonScanProperty(k, a[0].([]byte)) }
}

func TestFuzzJSONScanPropertyCanFail(t *testing.T) {
	fuzzseed.HoldsAndCanFail(t, append(fuzzseed.Corpus(t, "FuzzJSONScan"), jsonScanSeeds...), jsonScanWith(unmarshalKept), jsonScanWith(firstKept))
}

// --- FuzzSSE ---

// fuzzSSELine is the line bound the fuzz target reads with: small, so the fuzzer reaches it.
const fuzzSSELine = 64

// sseRead reads every event of a stream delivered as chunks (one Read each), and the error that
// ended it (nil for io.EOF).
type sseRead func(chunks [][]byte, maxLine int) ([]sseEvent, error)

func readAll(r *sseReader) ([]sseEvent, error) {
	var evs []sseEvent
	for {
		ev, err := r.next()
		if errors.Is(err, io.EOF) {
			return evs, nil
		}
		if err != nil {
			return evs, err
		}
		evs = append(evs, ev)
	}
}

// oneReader is the reference: one reader over the chunks in turn.
func oneReader(chunks [][]byte, maxLine int) ([]sseEvent, error) {
	rs := make([]io.Reader, len(chunks))
	for i, c := range chunks {
		rs[i] = bytes.NewReader(c)
	}
	return readAll(newSSEReaderSize(io.MultiReader(rs...), maxLine))
}

// readerPerChunk is the wrong reference: a fresh reader for each chunk, as a reader that lost
// its state at a read boundary would.
func readerPerChunk(chunks [][]byte, maxLine int) ([]sseEvent, error) {
	var all []sseEvent
	for _, c := range chunks {
		evs, err := readAll(newSSEReaderSize(bytes.NewReader(c), maxLine))
		all = append(all, evs...)
		if err != nil {
			return all, err
		}
	}
	return all, nil
}

// sseProperty: no event holds a line (a data line or the event name) longer than the bound, and
// the stream read whole, split at split, and one byte a read gives the same events and the same
// end (a line over the bound is an error, never a truncated line).
func sseProperty(read sseRead, stream []byte, split uint) error {
	k := int(split % uint(len(stream)+1))
	whole, werr := read([][]byte{stream}, fuzzSSELine)
	for _, ev := range whole {
		if len(ev.event) > fuzzSSELine {
			return fmt.Errorf("an event name of %d bytes, over the bound %d", len(ev.event), fuzzSSELine)
		}
		for _, l := range strings.Split(ev.data, "\n") {
			if len(l) > fuzzSSELine {
				return fmt.Errorf("a data line of %d bytes, over the bound %d", len(l), fuzzSSELine)
			}
		}
	}
	bytewise := make([][]byte, len(stream))
	for i := range stream {
		bytewise[i] = stream[i : i+1]
	}
	for name, chunks := range map[string][][]byte{"split": {stream[:k], stream[k:]}, "one byte a read": bytewise} {
		got, err := read(chunks, fuzzSSELine)
		if !reflect.DeepEqual(got, whole) || (err == nil) != (werr == nil) {
			return fmt.Errorf("%q read %s (at %d) gives %q, %v; read whole %q, %v", stream, name, k, got, err, whole, werr)
		}
	}
	return nil
}

var sseSeeds = [][]any{
	{[]byte("data: {\"a\":1}\n\ndata: [DONE]\n\n"), uint(9)},
	{[]byte("event: message_start\r\ndata: x\r\ndata: y\r\n\r\n: comment\n\nretry: 5\ndata:z"), uint(17)},
	{[]byte("\n\n\ndata\n\nevent:e\n\n"), uint(3)},
	{[]byte("data: " + strings.Repeat("x", fuzzSSELine) + "\n\n"), uint(30)},
	{[]byte(""), uint(0)},
}

func FuzzSSE(f *testing.F) {
	for _, s := range sseSeeds {
		f.Add(s[0].([]byte), s[1].(uint))
	}
	f.Fuzz(func(t *testing.T, stream []byte, split uint) {
		if err := sseProperty(oneReader, stream, split); err != nil {
			t.Fatal(err)
		}
	})
}

func sseWith(r sseRead) func([]any) error {
	return func(a []any) error { return sseProperty(r, a[0].([]byte), a[1].(uint)) }
}

func TestFuzzSSEPropertyCanFail(t *testing.T) {
	fuzzseed.HoldsAndCanFail(t, append(fuzzseed.Corpus(t, "FuzzSSE"), sseSeeds...), sseWith(oneReader), sseWith(readerPerChunk))
}

// The production reader keeps its own bound and its first buffer.
func TestSSEReaderBound(t *testing.T) {
	long := "data: " + strings.Repeat("x", fuzzSSELine) + "\n\n"
	if _, err := readAll(newSSEReaderSize(strings.NewReader(long), fuzzSSELine)); err == nil {
		t.Error("a line over the bound was read")
	}
	if evs, err := readAll(newSSEReader(strings.NewReader(long))); err != nil || len(evs) != 1 {
		t.Errorf("the production bound refused a %d-byte line: %v, %v", len(long), evs, err)
	}
}

// --- FuzzParseConfig ---

// configEncoder encodes an accepted config for the property to re-parse.
type configEncoder func(c *Config) ([]byte, error)

// marshalConfig is the reference: encoding/json, as the renderer's output is read.
func marshalConfig(c *Config) ([]byte, error) { return json.Marshal(c) }

// dropRoles is the wrong reference: an encoder that loses the roles, so the re-parse cannot give
// the value back. A property that no longer re-parses and compares stays green on it.
func dropRoles(c *Config) ([]byte, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	delete(m, "roles")
	return json.Marshal(m)
}

// parseConfigProperty: a config ParseConfig accepts encodes, the encoding is accepted, and it
// parses to a value equal to the first; a refusal is a ConfigError with problems. The schema
// subset half of ADR-0048's property waits for that validator's move to a package the gateway's
// tests can import (ADR-0048, implementation plan, the note of 2026-11-08 at step 4); until then
// the shared vectors hold the reader to the schema.
func parseConfigProperty(encode configEncoder, data []byte) error {
	c, err := ParseConfig(data)
	if err != nil {
		var ce *ConfigError
		if !errors.As(err, &ce) || len(ce.Problems) == 0 {
			return fmt.Errorf("ParseConfig refuses with %T %v, not a ConfigError with problems", err, err)
		}
		return nil
	}
	b, err := encode(c)
	if err != nil {
		return fmt.Errorf("an accepted config does not encode: %v", err)
	}
	c2, err := ParseConfig(b)
	if err != nil {
		return fmt.Errorf("an accepted config re-encodes to %s, which is refused: %v", b, err)
	}
	if !reflect.DeepEqual(c, c2) {
		return fmt.Errorf("an accepted config re-parses to a different value: %+v, then %+v", c, c2)
	}
	return nil
}

// contractSeeds are the contract's examples and negatives, read in place.
func contractSeeds(tb testing.TB) [][]any {
	tb.Helper()
	var out [][]any
	for _, kind := range []string{"examples", "negative"} {
		paths, err := filepath.Glob(filepath.Join(schemaDir, kind, "gateway_config.*.json"))
		if err != nil || len(paths) == 0 {
			tb.Fatalf("no %s of the gateway config contract under %s (%v)", kind, schemaDir, err)
		}
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if err != nil {
				tb.Fatal(err)
			}
			out = append(out, []any{data})
		}
	}
	return out
}

// FuzzParseConfig's committed corpus adds what the contract's files cannot hold:
// case-variant-key spells one key twice in two cases, which encoding/json would read as one
// field (it matches names case-insensitively and keeps the last) and ParseConfig must refuse
// before decoding; a JSON Schema instance file cannot carry that refusal as a negative.
func FuzzParseConfig(f *testing.F) {
	for _, s := range contractSeeds(f) {
		f.Add(s[0].([]byte))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := parseConfigProperty(marshalConfig, data); err != nil {
			t.Fatal(err)
		}
	})
}

func parseConfigWith(e configEncoder) func([]any) error {
	return func(a []any) error { return parseConfigProperty(e, a[0].([]byte)) }
}

func TestFuzzParseConfigPropertyCanFail(t *testing.T) {
	fuzzseed.HoldsAndCanFail(t, append(fuzzseed.Corpus(t, "FuzzParseConfig"), contractSeeds(t)...), parseConfigWith(marshalConfig), parseConfigWith(dropRoles))
}
