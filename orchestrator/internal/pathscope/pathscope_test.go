// SPDX-License-Identifier: Apache-2.0

package pathscope

import (
	"errors"
	"testing"
)

// A fictional tree: owner/ holds an operator's decisions (readable, never writable),
// notes/findings/ the agents' findings, inbox/ the pending work every lane writes.
var testZones = mustZones(Zones{
	DeniedRoots:   []string{"owner"},
	FindingsRoot:  "notes/findings/",
	SharedWrite:   []string{"inbox/"},
	ReservedNames: []string{"operator"},
})

func mustZones(z Zones) Zones {
	v, err := NewZones(z)
	if err != nil {
		panic(err)
	}
	return v
}

var testScope = Scope{
	WritablePrefixes: []string{"notes/findings/pipeline/", "inbox/"},
	ReadablePrefixes: []string{"owner/approved/", "owner/denied/", "owner/done/"},
}

func TestCheckWrite_AllowedPrefixSucceeds(t *testing.T) {
	for _, p := range []string{"notes/findings/pipeline/2026-01-01-0900-pipeline.md", "inbox/2026-01-01-watcher-fix.md", "/inbox/x.md"} {
		if err := CheckWrite(testScope, p); err != nil {
			t.Errorf("CheckWrite(%q) = %v, want nil", p, err)
		}
	}
}

func TestCheckWrite_DisallowedPrefixFails(t *testing.T) {
	if err := CheckWrite(testScope, "notes/findings/other/x.md"); !errors.Is(err, ErrDenied) {
		t.Fatalf("CheckWrite = %v, want ErrDenied", err)
	}
}

func TestCheckWrite_ReadableOnlyIsNeverWritable(t *testing.T) {
	for _, p := range []string{"owner/approved/x.md", "owner/denied/x.md", "owner/done/x.md", "owner/other/x.md"} {
		if err := CheckWrite(testScope, p); !errors.Is(err, ErrDenied) {
			t.Errorf("CheckWrite(%q) = %v, want ErrDenied", p, err)
		}
	}
}

func TestCheckWrite_TraversalOutOfAWritablePrefixIsDenied(t *testing.T) {
	// cleans to owner/approved/evil.md, outside every writable prefix
	if err := CheckWrite(testScope, "notes/findings/pipeline/../../../owner/approved/evil.md"); !errors.Is(err, ErrDenied) {
		t.Fatalf("CheckWrite(traversal) = %v, want ErrDenied", err)
	}
	// climbs past the root: cleans to ../.., which no relative prefix matches
	if err := CheckWrite(testScope, "../../../etc/passwd"); !errors.Is(err, ErrDenied) {
		t.Fatalf("CheckWrite(climb past the root) = %v, want ErrDenied", err)
	}
}

func TestCheckRead(t *testing.T) {
	// writable implies readable: a caller can read what it wrote
	for _, p := range []string{"notes/findings/pipeline/x.md", "inbox/x.md", "owner/approved/2026-01-01-x.md"} {
		if err := CheckRead(testScope, p); err != nil {
			t.Errorf("CheckRead(%q) = %v, want nil", p, err)
		}
	}
	// no wildcard: a sub-zone no prefix names is denied
	if err := CheckRead(testScope, "owner/other/x.md"); !errors.Is(err, ErrDenied) {
		t.Fatalf("CheckRead(unlisted sub-zone) = %v, want ErrDenied", err)
	}
}

// The prefix boundary is a path segment, whether or not the entry ends in "/".
func TestCheckWrite_PrefixBoundaryIsASegment(t *testing.T) {
	s := Scope{WritablePrefixes: []string{"notes/findings/pipeline"}}
	if err := CheckWrite(s, "notes/findings/pipeline-other/x.md"); !errors.Is(err, ErrDenied) {
		t.Errorf("CheckWrite(sibling with the same stem) = %v, want ErrDenied", err)
	}
	for _, p := range []string{"notes/findings/pipeline/x.md", "notes/findings/pipeline"} {
		if err := CheckWrite(s, p); err != nil {
			t.Errorf("CheckWrite(%q) = %v, want nil", p, err)
		}
	}
}

// A readable prefix may name one file. It grants exactly that file: not a sibling, not a name
// that merely starts the same, not the zone.
var fileScope = Scope{
	WritablePrefixes: []string{"notes/findings/network/"},
	ReadablePrefixes: []string{"owner/priorities.md", "owner/approved/"},
}

func TestCheckRead_SingleFilePrefixGrantsExactlyThatFile(t *testing.T) {
	for _, p := range []string{"owner/priorities.md", "/owner/priorities.md", "owner/approved/../priorities.md"} {
		if err := CheckRead(fileScope, p); err != nil {
			t.Errorf("CheckRead(%q) = %v, want nil (the granted file)", p, err)
		}
	}
	for _, p := range []string{
		"owner/instructions.md",
		"owner/priorities.md.bak",
		"owner/priorities.md2",
		"owner/notes/x.md",
		"owner",
		"owner/",
		"owner/priorities.md/../instructions.md", // cleans to the sibling
		"owner/approved/../priorities.md/../notes/x.md",
	} {
		if err := CheckRead(fileScope, p); !errors.Is(err, ErrDenied) {
			t.Errorf("CheckRead(%q) = %v, want ErrDenied", p, err)
		}
	}
	if err := CheckWrite(fileScope, "owner/priorities.md"); !errors.Is(err, ErrDenied) {
		t.Errorf("a readable file is writable: %v", err)
	}
}

// A Scope built without ValidatePrefix may hold a ".." entry. Cleaning it would make a new entry
// the scope never named ({"a/x/../../owner/"} would allow owner/approved/a.md), so such entries,
// absolute ones and root-like ones match nothing.
func TestMalformedScopeEntriesMatchNothing(t *testing.T) {
	for _, c := range []struct{ entry, path string }{
		{"notes/x/../../owner/", "owner/approved/a.md"},
		{"notes/../../etc/", "../etc/passwd"},
		{"notes/../inbox/", "inbox/a.md"},
		{"../etc/", "../etc/passwd"},
		{"..", "../x"},
		{"/notes/findings/x/", "notes/findings/x/a.md"},
		{"/", "notes/a.md"},
		{"", "notes/a.md"},
		{"./", "notes/a.md"},
		{".//", "notes/a.md"},
	} {
		s := Scope{WritablePrefixes: []string{c.entry}, ReadablePrefixes: []string{c.entry}}
		if err := CheckWrite(s, c.path); !errors.Is(err, ErrDenied) {
			t.Errorf("CheckWrite under %q allowed %q (err %v)", c.entry, c.path, err)
		}
		if err := CheckRead(s, c.path); !errors.Is(err, ErrDenied) {
			t.Errorf("CheckRead under %q allowed %q (err %v)", c.entry, c.path, err)
		}
		if Within(c.path, []string{c.entry}) {
			t.Errorf("Within(%q, %q) = true", c.path, c.entry)
		}
	}
	// a clean entry beside a malformed one still works
	s := Scope{WritablePrefixes: []string{"notes/x/../../owner/", "notes/findings/x/"}}
	if err := CheckWrite(s, "notes/findings/x/a.md"); err != nil {
		t.Errorf("the clean entry stopped matching: %v", err)
	}
}

// An unclean entry ("a/./b/", "a//b/") names exactly the directory it spells.
func TestUncleanScopeEntriesNameTheDirectoryTheySpell(t *testing.T) {
	for _, entry := range []string{"notes/./findings/x/", "notes//findings/x/"} {
		within := []string{entry}
		if !Within("notes/findings/x/sub/", within) || !Within("notes/findings/x", within) {
			t.Errorf("Within under %q: the directory it names is not matched", entry)
		}
		if Within("notes/findings/", within) || Within("notes/findings/xy/", within) {
			t.Errorf("Within under %q matches more than the directory it names", entry)
		}
		if err := CheckWrite(Scope{WritablePrefixes: within}, "notes/findings/x/f.md"); err != nil {
			t.Errorf("CheckWrite under %q: %v", entry, err)
		}
	}
}

func TestWithin(t *testing.T) {
	within := []string{"notes/findings/a/", "inbox/"}
	for _, p := range []string{"notes/findings/a/", "notes/findings/a", "notes/findings/a/sub/", "./inbox/"} {
		if !Within(p, within) {
			t.Errorf("Within(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"notes/findings/", "notes/findings/ab/", "notes", "config", "owner/approved/"} {
		if Within(p, within) {
			t.Errorf("Within(%q) = true, want false", p)
		}
	}
}

func TestShadowMarked(t *testing.T) {
	for _, v := range []string{"notes/findings/watch-shadow/", "import_state-shadow.json", "shadow/", "x.shadow", "SHADOW"} {
		if !ShadowMarked(v) {
			t.Errorf("ShadowMarked(%q) = false", v)
		}
	}
	for _, v := range []string{"notes/findings/watch/", "shadowy/", "foreshadow.md", ""} {
		if ShadowMarked(v) {
			t.Errorf("ShadowMarked(%q) = true", v)
		}
	}
}
