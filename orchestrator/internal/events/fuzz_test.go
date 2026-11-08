// SPDX-License-Identifier: Apache-2.0

package events

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/homelab-next/homelab-next/orchestrator/internal/fuzzseed"
)

// FuzzDeriveID (ADR-0048 decision 1): asciiJSON is pure ASCII, decodes to its input strings (or,
// for invalid UTF-8, to them with each invalid byte replaced by U+FFFD), and is byte for byte the
// encoding Python's json.dumps(..., separators=(",", ":"), ensure_ascii=True) writes, which
// pythonJSON below spells out independently; DeriveID is deterministic, has the id's shape and is
// the hash of that encoding. The seeds include every shared vector of
// conformance/fixtures/event_id_vectors.json, read in place.

// decoded is what the encoding of s must decode to.
type decodedRef func(s string) string

// perByte is the reference: encoding/json, like Python reading the bytes as surrogate escapes and
// replacing them, turns each invalid byte into one U+FFFD; a Go conversion to runes does the same.
func perByte(s string) string { return string([]rune(s)) }

// collapsed is the wrong reference: one U+FFFD for each run of invalid bytes.
func collapsed(s string) string { return strings.ToValidUTF8(s, "�") }

// pythonJSON is the reference encoding of a list of strings: json.dumps with compact separators
// and ensure_ascii, written from Python's rules (the short escapes, \u00XX for the other C0
// controls and DEL, \uXXXX lowercase for every other non-ASCII character, a surrogate pair above
// the BMP), not from encoding/json.
func pythonJSON(fields []string) []byte {
	var b strings.Builder
	b.WriteByte('[')
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		for _, r := range f {
			switch {
			case r == '"':
				b.WriteString(`\"`)
			case r == '\\':
				b.WriteString(`\\`)
			case r == '\n':
				b.WriteString(`\n`)
			case r == '\r':
				b.WriteString(`\r`)
			case r == '\t':
				b.WriteString(`\t`)
			case r == '\b':
				b.WriteString(`\b`)
			case r == '\f':
				b.WriteString(`\f`)
			case r < 0x20 || r == 0x7f:
				fmt.Fprintf(&b, `\u%04x`, r)
			case r < 0x80:
				b.WriteRune(r)
			case r > 0xffff:
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
			default:
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		}
		b.WriteByte('"')
	}
	b.WriteByte(']')
	return []byte(b.String())
}

var eventIDShape = regexp.MustCompile(`^evt-[0-9a-f]{32}$`)

func deriveIDProperty(want decodedRef, eventType, source, subject, dedupeKey string) error {
	in := []string{eventType, source, subject, dedupeKey}
	enc := asciiJSON(in)
	for i, c := range enc {
		if c >= 0x80 {
			return fmt.Errorf("asciiJSON(%q) holds the non-ASCII byte %#x at %d", in, c, i)
		}
	}
	var got []string
	if err := json.Unmarshal(enc, &got); err != nil {
		return fmt.Errorf("asciiJSON(%q) = %s does not decode: %v", in, enc, err)
	}
	for i := range in {
		if i >= len(got) || got[i] != want(in[i]) {
			return fmt.Errorf("asciiJSON(%q) decodes to %q, want %q at %d", in, got, want(in[i]), i)
		}
	}
	norm := make([]string, len(in))
	for i, s := range in {
		norm[i] = perByte(s)
	}
	if py := pythonJSON(norm); string(py) != string(enc) {
		return fmt.Errorf("asciiJSON(%q) = %s, Python writes %s", in, enc, py)
	}
	id := DeriveID(eventType, source, subject, dedupeKey)
	if again := DeriveID(eventType, source, subject, dedupeKey); again != id {
		return fmt.Errorf("DeriveID is not deterministic: %s then %s", id, again)
	}
	sum := sha256.Sum256(enc)
	if !eventIDShape.MatchString(id) || id != "evt-"+hex.EncodeToString(sum[:])[:32] {
		return fmt.Errorf("DeriveID(%q) = %s, not evt- and the first 32 hex characters of the SHA-256 of %s", in, id, enc)
	}
	return nil
}

// deriveIDSeeds are the package's table-test inputs; the shared vectors are added from the file.
var deriveIDSeeds = [][]any{
	{"homelabnext.agent.job.started", "svc:orchestrator", "0123abcd", "0123abcd:homelabnext.agent.job.started"},
	{"t.x", "svc:a", "café", "\U0001F600<&>  "},
	{"t.x", "svc:a", "a\"b\\", "\x7f\x00\x1f\b\f\n\r\t"},
	{"t.x", "svc:a", "", ""},
}

type idVector struct {
	Type      string  `json:"type"`
	Source    string  `json:"source"`
	Subject   *string `json:"subject"`
	DedupeKey string  `json:"dedupe_key"`
	ID        string  `json:"id"`
}

func sharedVectors(tb testing.TB) []idVector {
	tb.Helper()
	data, err := os.ReadFile(eventIDVectors)
	if err != nil {
		tb.Fatal(err)
	}
	var file struct {
		Vectors []idVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil || len(file.Vectors) == 0 {
		tb.Fatalf("%s: %d vectors, %v", eventIDVectors, len(file.Vectors), err)
	}
	return file.Vectors
}

func (v idVector) args() []any {
	subject := ""
	if v.Subject != nil {
		subject = *v.Subject
	}
	return []any{v.Type, v.Source, subject, v.DedupeKey}
}

func FuzzDeriveID(f *testing.F) {
	seeds := deriveIDSeeds
	for _, v := range sharedVectors(f) {
		seeds = append(seeds, v.args())
	}
	for _, s := range seeds {
		f.Add(s[0].(string), s[1].(string), s[2].(string), s[3].(string))
	}
	f.Fuzz(func(t *testing.T, eventType, source, subject, dedupeKey string) {
		if err := deriveIDProperty(perByte, eventType, source, subject, dedupeKey); err != nil {
			t.Fatal(err)
		}
	})
}

func deriveIDWith(r decodedRef) func([]any) error {
	return func(a []any) error {
		return deriveIDProperty(r, a[0].(string), a[1].(string), a[2].(string), a[3].(string))
	}
}

func TestFuzzDeriveIDPropertyCanFail(t *testing.T) {
	seeds := append(fuzzseed.Corpus(t, "FuzzDeriveID"), deriveIDSeeds...)
	for _, v := range sharedVectors(t) {
		seeds = append(seeds, v.args())
	}
	fuzzseed.HoldsAndCanFail(t, seeds, deriveIDWith(perByte), deriveIDWith(collapsed))
}
