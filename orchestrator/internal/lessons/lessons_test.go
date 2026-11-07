// SPDX-License-Identifier: Apache-2.0

package lessons

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	certLesson    = "01a20000-0000-7000-8000-000000000001"
	diskLesson    = "01a20000-0000-7000-8000-000000000002"
	noMatchLesson = "01a20000-0000-7000-8000-000000000003"
	retiredLesson = "01a20000-0000-7000-8000-000000000004"
	practice      = "01a20000-0000-7000-8000-000000000005"
	certRunbook   = "01a20000-0000-7000-8000-000000000011"
)

// The fixtures are records in this repository's register format; tests/registers holds them to
// the register's own validation, so they cannot drift from it.
func testIndex(t *testing.T) *Index {
	t.Helper()
	ix, err := LoadIndex("testdata/lessons", "testdata/runbooks")
	if err != nil {
		t.Fatal(err)
	}
	return ix
}

func uids(hits []Hit) []string {
	var out []string
	for _, h := range hits {
		out = append(out, h.UID)
	}
	return out
}

func TestLoadIndex_ReadsTheRegisterFormat(t *testing.T) {
	ix := testIndex(t)
	l, r, unmatchable := ix.Counts()
	if l != 5 || r != 2 || unmatchable != 3 {
		t.Fatalf("Counts = %d lessons, %d runbooks, %d unmatchable", l, r, unmatchable)
	}
	les, ok := ix.LessonByUID(certLesson)
	if !ok || les.Title != "Certificate expired on the edge proxy" || !strings.HasPrefix(les.Symptom, "Every client failed") ||
		!strings.HasPrefix(les.PreventiveControl, "A daily client-side check") || !reflect.DeepEqual(les.Systems, []string{"proxy", "tls"}) {
		t.Errorf("lesson = %+v", les)
	}
	if p, ok := ix.LessonByUID(practice); !ok || !strings.HasPrefix(p.Method, "Rotate a job's logs") {
		t.Errorf("practice = %+v", p)
	}
	if rb, ok := ix.RunbookByUID(certRunbook); !ok || !strings.HasPrefix(rb.Purpose, "Restore a valid certificate") {
		t.Errorf("runbook = %+v", rb)
	}
}

// A lesson without match is never matched, and neither is an inactive one, however well its
// text fits the task.
func TestMatch_OnlyActiveRecordsWithAMatch(t *testing.T) {
	ix := testIndex(t)
	task := "The certificate expired on the edge proxy and every TLS handshake failed."
	got := uids(ix.MatchLessons(task, nil))
	if len(got) != 1 || got[0] != certLesson {
		t.Fatalf("MatchLessons = %v, want only %s", got, certLesson)
	}
	if _, ok := ix.LessonByUID(noMatchLesson); ok {
		t.Error("a lesson without match is in the index")
	}
	if _, ok := ix.LessonByUID(retiredLesson); ok {
		t.Error("a retired lesson is in the index")
	}
	if got := uids(ix.MatchRunbooks(task, nil)); len(got) != 1 || got[0] != certRunbook {
		t.Errorf("MatchRunbooks = %v", got)
	}
	if got := uids(ix.MatchRunbooks("free space: the disk is full", nil)); len(got) != 0 {
		t.Errorf("a runbook without match was matched: %v", got)
	}
}

func TestMatch_ScoringAndDeterminism(t *testing.T) {
	ix := testIndex(t)
	hits := ix.MatchLessons("Disk full again: no space left on the storage host", nil)
	if len(hits) != 1 || hits[0].UID != diskLesson || hits[0].Score != 2*wKeyword+wTag {
		t.Fatalf("hits = %+v", hits)
	}
	if !reflect.DeepEqual(hits[0].Why, []string{"keyword:disk full", "keyword:no space left", "tag:storage"}) {
		t.Errorf("why = %v", hits[0].Why)
	}
	// a path the task names scores the record's path prefix
	p := ix.MatchLessons("tidy the role", []string{"roles/proxy/tasks/main.yml"})
	if len(p) != 1 || p[0].UID != certLesson || p[0].Why[0] != "path:roles/proxy/" {
		t.Errorf("path hits = %+v", p)
	}
	// keywords are case-insensitive substrings, never patterns
	if got := uids(ix.MatchLessons("CERTIFICATE EXPIRED", nil)); len(got) != 1 {
		t.Errorf("case-insensitive keyword: %v", got)
	}
	if got := uids(ix.MatchLessons("certificate.*expired", nil)); len(got) != 0 {
		t.Errorf("a keyword was read as a pattern: %v", got)
	}
	task := "certificate expired, tls handshake failed, disk full, log rotation"
	first := ix.MatchLessons(task, []string{"roles/proxy/x"})
	for range 20 {
		if again := ix.MatchLessons(task, []string{"roles/proxy/x"}); !reflect.DeepEqual(again, first) {
			t.Fatalf("one input, two answers: %+v vs %+v", first, again)
		}
	}
	if len(first) != 3 || first[0].UID != certLesson {
		t.Errorf("ranked = %+v", first)
	}
}

// copyRegister copies the fixtures' lessons into a fresh directory.
func copyRegister(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files, _ := filepath.Glob("testdata/lessons/*.md")
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(f)), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func writeEvent(t *testing.T, dir, uid, name, body string) {
	t.Helper()
	ev := filepath.Join(dir, uid+".events")
	if err := os.MkdirAll(ev, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ev, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A lesson's status is its record's after its transition events, as the register applies them:
// a lesson retired by an event is no longer matched, and a chain that does not start where the
// record is refuses the register rather than guess.
func TestLoadIndex_AppliesTransitionEvents(t *testing.T) {
	dir := copyRegister(t)
	writeEvent(t, dir, certLesson, "20261020T000000Z-review-agent-example-checker.yml", "event: review\n")
	writeEvent(t, dir, certLesson, "20261021T000000Z-transition-human-example-operator.yml",
		"event: transition\nfrom: open\nto: retired\nset: {retired_on: 2026-10-21, retired_by: [make:check]}\nintent: retire\n")
	ix, err := LoadIndex(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ix.LessonByUID(certLesson); ok {
		t.Fatal("a lesson retired by a transition event is still matched")
	}
	writeEvent(t, dir, certLesson, "20261022T000000Z-transition-human-example-operator.yml", "event: transition\nfrom: open\nto: partial\n")
	if _, err := LoadIndex(dir, ""); err == nil || !strings.Contains(err.Error(), "transition from") {
		t.Fatalf("a broken transition chain loaded: %v", err)
	}
}

func TestLoadIndex_RefusesWhatItCannotRead(t *testing.T) {
	good, err := os.ReadFile("testdata/lessons/" + certLesson + ".md")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"no front matter":   "uid: x\n",
		"unclosed":          "---\nuid: " + certLesson + "\n",
		"not a mapping":     "---\n- a\n---\n",
		"repeated key":      strings.Replace(string(good), "kind: pitfall\n", "kind: pitfall\nkind: practice\n", 1),
		"uid not the name":  strings.Replace(string(good), "uid: "+certLesson, "uid: 01a20000-0000-7000-8000-0000000000ff", 1),
		"wrong type":        strings.Replace(string(good), "type: lesson", "type: runbook", 1),
		"section twice":     string(good) + "\n## Symptom\n\nagain\n",
		"empty match":       strings.Replace(string(good), "  keywords: [certificate expired, tls handshake]\n  paths: [roles/proxy/]\n", "  {}\n", 1),
		"short keyword":     strings.Replace(string(good), "[certificate expired, tls handshake]", "[ab]", 1),
		"long keyword":      strings.Replace(string(good), "[certificate expired, tls handshake]", "["+strings.Repeat("k", MaxKeywordLength+1)+"]", 1),
		"keyword control":   strings.Replace(string(good), "[certificate expired, tls handshake]", "[\"certificate\\u200bexpired\"]", 1),
		"keyword twice":     strings.Replace(string(good), "[certificate expired, tls handshake]", "[TLS handshake, tls handshake]", 1),
		"too many keywords": strings.Replace(string(good), "[certificate expired, tls handshake]", "["+strings.Repeat("abc, ", MaxMatchItems)+"abcd]", 1),
		"absolute path":     strings.Replace(string(good), "[roles/proxy/]", "[/etc/proxy/]", 1),
		"traversal path":    strings.Replace(string(good), "[roles/proxy/]", "[roles/../secrets/]", 1),
		"unclean path":      strings.Replace(string(good), "[roles/proxy/]", "[roles//proxy/]", 1),
		"regex key":         strings.Replace(string(good), "  paths: [roles/proxy/]\n", "  pattern: \"cert.*\"\n", 1),
	}
	for name, body := range cases {
		if body == string(good) {
			t.Fatalf("%s: the replacement did not apply", name)
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, certLesson+".md"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadIndex(dir, ""); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	// a file named like a record that is not a uid, and a symbolic link, are refused too
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "LL-001.md"), good, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIndex(dir, ""); err == nil {
		t.Error("a record file not named for a uid loaded")
	}
	dir = t.TempDir()
	abs, _ := filepath.Abs("testdata/lessons/" + certLesson + ".md")
	if err := os.Symlink(abs, filepath.Join(dir, certLesson+".md")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIndex(dir, ""); err == nil {
		t.Error("a symbolic link loaded as a record")
	}
}

func TestLoadConfigured(t *testing.T) {
	if ix, err := LoadConfigured("", ""); ix != nil || err != nil {
		t.Fatalf("both empty = %v, %v", ix, err)
	}
	if _, err := LoadConfigured("", "testdata/runbooks"); err == nil {
		t.Error("runbooks without lessons loaded")
	}
	if _, err := LoadConfigured(t.TempDir(), ""); err == nil {
		t.Error("an empty lessons register loaded")
	}
	if _, err := LoadConfigured("testdata/lessons", t.TempDir()); err == nil {
		t.Error("an empty runbooks register loaded")
	}
	if _, err := LoadConfigured(filepath.Join(t.TempDir(), "absent"), ""); err == nil {
		t.Error("a missing lessons register loaded")
	}
	if _, err := LoadConfigured("testdata/lessons", "testdata/runbooks"); err != nil {
		t.Fatal(err)
	}
}

// This repository's own example registers load in place, and since none of their records
// declares a match, none is ever injected, however well a task names it.
func TestTheExampleRegistersLoadAndNothingIsMatchedWithoutAMatch(t *testing.T) {
	root := filepath.Join("..", "..", "..", "examples", "registers")
	ix, err := LoadConfigured(filepath.Join(root, "lessons"), filepath.Join(root, "runbooks"))
	if err != nil {
		t.Fatal(err)
	}
	l, r, unmatchable := ix.Counts()
	if l == 0 || r == 0 || unmatchable != l+r {
		t.Fatalf("Counts = %d, %d, %d", l, r, unmatchable)
	}
	task := "Certificate expired on the internal reverse proxy: renew the internal proxy certificate"
	if got := ResolveContext(ix, task); got != "" {
		t.Errorf("a record without match was injected:\n%s", got)
	}
}

// The match bounds are the schemas' (lesson 2.2, runbook 2.3), read in place.
func TestMatchBoundsAreTheSchemas(t *testing.T) {
	for _, name := range []string{"lesson", "runbook"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "schemas", "registers", name+".schema.json"))
		if err != nil {
			t.Fatal(err)
		}
		var s struct {
			Properties struct {
				Match struct {
					Properties struct {
						Keywords struct {
							MaxItems int `json:"maxItems"`
							Items    struct {
								MinLength int `json:"minLength"`
								MaxLength int `json:"maxLength"`
							} `json:"items"`
						} `json:"keywords"`
						Paths struct {
							MaxItems int `json:"maxItems"`
							Items    struct {
								MaxLength int `json:"maxLength"`
							} `json:"items"`
						} `json:"paths"`
					} `json:"properties"`
				} `json:"match"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		m := s.Properties.Match.Properties
		if m.Keywords.MaxItems != MaxMatchItems || m.Paths.MaxItems != MaxMatchItems || m.Keywords.Items.MinLength != MinKeywordLength ||
			m.Keywords.Items.MaxLength != MaxKeywordLength || m.Paths.Items.MaxLength != MaxPathLength {
			t.Errorf("%s schema match bounds %+v differ from the reader's", name, m)
		}
	}
}
