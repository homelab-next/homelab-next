// SPDX-License-Identifier: Apache-2.0

package pathscope

import (
	"errors"
	"strings"
	"testing"
)

func TestValidatePrefix(t *testing.T) {
	for _, p := range []string{"notes/findings/a/", "inbox/", "inbox", "owners/", "notes/owner/"} {
		if err := testZones.ValidatePrefix(p, true); err != nil {
			t.Errorf("ValidatePrefix(%q, writable) = %v, want nil", p, err)
		}
	}
	for _, p := range []string{"owner/approved/", "owner/priorities.md"} {
		if err := testZones.ValidatePrefix(p, false); err != nil {
			t.Errorf("ValidatePrefix(%q, readable) = %v, want nil", p, err)
		}
	}
	for _, p := range []string{
		// a denied root, in any case and any spelling
		"owner", "owner/", "Owner/", "OWNER/approved", "./owner/", "owner//approved/", "./owner",
		// not a plain relative path
		"", " ", " inbox/", "inbox/ ", "/srv/x", "~/x", "..", "../x", "a/../owner",
		"notes/..", "a\\b", "a\x00b", ".", "./", "//",
		// not clean: compared as written, these would not equal the path they name
		"./inbox/", "notes/./findings/x/", "notes//findings/x/", "notes/findings/x//", "notes/findings/x/.",
	} {
		if err := testZones.ValidatePrefix(p, true); !errors.Is(err, ErrBadPrefix) {
			t.Errorf("ValidatePrefix(%q, writable) = %v, want ErrBadPrefix", p, err)
		}
	}
	for _, p := range []string{"..", "a/../b", "/owner/x", ".", "", "./inbox/", "notes/./findings/x/", "notes//findings/x/"} {
		if err := testZones.ValidatePrefix(p, false); !errors.Is(err, ErrBadPrefix) {
			t.Errorf("ValidatePrefix(%q, readable) = %v, want ErrBadPrefix", p, err)
		}
	}
}

func TestValidatePrefix_RefusesHiddenSegmentsAndControls(t *testing.T) {
	for _, p := range []string{".git", ".git/", "docs/.env", ".env", "a/.b/c", "./.git", "src/.github/", "a\nb", "a\rb", "a\u2028b", "a\u0085b", "a\tb"} {
		for _, writable := range []bool{false, true} {
			if err := testZones.ValidatePrefix(p, writable); !errors.Is(err, ErrBadPrefix) {
				t.Errorf("ValidatePrefix(%q, %v) = %v, want ErrBadPrefix", p, writable, err)
			}
		}
	}
	for _, p := range []string{"inbox/", "dev/lessons.yml", "a.b/c", "docs/v1.2/"} {
		if err := testZones.ValidatePrefix(p, false); err != nil {
			t.Errorf("ValidatePrefix(%q) = %v, want nil", p, err)
		}
	}
}

// A Zones with no denied roots is refused unless it says so on purpose, so a missing scope block
// cannot make every root writable; with the opt-out, no root is refused for its zone.
func TestZonesWithNoDeniedRootIsRefusedUnlessAllowed(t *testing.T) {
	for _, z := range []Zones{{}, {FindingsRoot: "notes/findings/"}, {DeniedRoots: []string{}}} {
		if _, err := NewZones(z); !errors.Is(err, ErrBadPrefix) || !strings.Contains(err.Error(), "allow_no_denied_roots") {
			t.Errorf("NewZones(%+v) = %v, want a refusal naming allow_no_denied_roots", z, err)
		}
	}
	z := mustZones(Zones{AllowNoDeniedRoots: true})
	for _, p := range []string{"owner/", "decisions/", "anything/x/"} {
		if err := z.ValidatePrefix(p, true); err != nil {
			t.Errorf("opted-out Zones refused %q: %v", p, err)
		}
	}
	if err := z.ValidateVerdictPrefix("notes/findings/x/"); !errors.Is(err, ErrBadPrefix) {
		t.Errorf("a verdict directory with no findings root configured = %v, want ErrBadPrefix", err)
	}
	if z.ReservedName("operator") {
		t.Error("a Zones with no reserved names reserves one")
	}
}

// Every method of a Zones that did not come from NewZones refuses, so a value decoded from
// configuration cannot be used without its checks.
func TestUnvalidatedZonesRefuseEverything(t *testing.T) {
	raw := Zones{DeniedRoots: []string{"owner"}, FindingsRoot: "notes/findings/"}
	if err := raw.ValidatePrefix("inbox/", false); !errors.Is(err, ErrBadPrefix) {
		t.Errorf("ValidatePrefix on raw Zones = %v", err)
	}
	if err := raw.ValidateDirPrefix("inbox/"); !errors.Is(err, ErrBadPrefix) {
		t.Errorf("ValidateDirPrefix on raw Zones = %v", err)
	}
	if err := raw.ValidateVerdictPrefix("notes/findings/x/"); !errors.Is(err, ErrBadPrefix) {
		t.Errorf("ValidateVerdictPrefix on raw Zones = %v", err)
	}
	if _, err := raw.NewScope([]string{"inbox/"}, nil); !errors.Is(err, ErrBadPrefix) {
		t.Errorf("NewScope on raw Zones = %v", err)
	}
	if !raw.ReservedName("anyone") {
		t.Error("raw Zones must reserve every name")
	}
	if raw.Validated() || !testZones.Validated() {
		t.Errorf("Validated: raw %v, validated %v", raw.Validated(), testZones.Validated())
	}
	changed := testZones
	changed.SharedWrite = []string{"other/"}
	if changed.Validated() {
		t.Error("a validated Zones changed afterwards still reports Validated")
	}
}

// The validated copy owns its lists.
func TestValidatedZonesOwnTheirLists(t *testing.T) {
	roots := []string{"owner"}
	z := mustZones(Zones{DeniedRoots: roots})
	roots[0] = "other"
	if err := z.ValidatePrefix("owner/x/", true); !errors.Is(err, ErrBadPrefix) {
		t.Errorf("changing the caller's slice changed the validated Zones: %v", err)
	}
}

// A validated Zones cannot be changed afterwards: changing a field or an element of a list
// makes it refuse everything (never a decision on unchecked values), and validating it again
// makes the change take effect, checked.
func TestValidatedZonesCannotBeChangedAfterwards(t *testing.T) {
	base := Zones{DeniedRoots: []string{"owner"}, FindingsRoot: "notes/findings/", SharedWrite: []string{"inbox/"}, ReservedNames: []string{"operator"}}
	for name, change := range map[string]func(z *Zones){
		"denied root element":  func(z *Zones) { z.DeniedRoots[0] = "other" },
		"denied roots":         func(z *Zones) { z.DeniedRoots = nil },
		"findings root":        func(z *Zones) { z.FindingsRoot = "inbox/" },
		"shared write element": func(z *Zones) { z.SharedWrite[0] = "notes/" },
		"shared write":         func(z *Zones) { z.SharedWrite = append(z.SharedWrite, "x/") },
		"reserved name":        func(z *Zones) { z.ReservedNames[0] = "nobody" },
		"opt-out":              func(z *Zones) { z.AllowNoDeniedRoots = true },
	} {
		t.Run(name, func(t *testing.T) {
			z := mustZones(base)
			copyBefore := z // a copy taken before the change shares the lists, and refuses too
			change(&z)
			for label, v := range map[string]Zones{"changed": z, "copy": copyBefore} {
				if label == "copy" && !strings.Contains(name, "element") {
					continue // replacing a field changes only the value it is set on
				}
				if err := v.ValidatePrefix("owner/x/", true); !errors.Is(err, ErrBadPrefix) {
					t.Errorf("%s: a denied root became writable: %v", label, err)
				}
				if err := v.ValidatePrefix("inbox/", false); !errors.Is(err, ErrBadPrefix) {
					t.Errorf("%s: a changed Zones still decides: %v", label, err)
				}
				if err := v.ValidateDirPrefix("notes/findings/a/"); !errors.Is(err, ErrBadPrefix) {
					t.Errorf("%s: ValidateDirPrefix = %v", label, err)
				}
				if err := v.ValidateVerdictPrefix("notes/findings/a/"); !errors.Is(err, ErrBadPrefix) {
					t.Errorf("%s: ValidateVerdictPrefix = %v", label, err)
				}
				if !v.ReservedName("anyone") {
					t.Errorf("%s: a changed Zones does not reserve every name", label)
				}
			}
		})
	}
	z := mustZones(base)
	z.DeniedRoots = []string{"other"}
	z, err := z.Validate()
	if err != nil {
		t.Fatal(err)
	}
	if err := z.ValidatePrefix("owner/x/", true); err != nil {
		t.Errorf("revalidated: %v", err)
	}
	if err := z.ValidatePrefix("other/x/", true); !errors.Is(err, ErrBadPrefix) {
		t.Errorf("revalidated: the new denied root is writable: %v", err)
	}
	if untouched := mustZones(base); untouched.ValidatePrefix("inbox/", true) != nil || untouched.ReservedName("anyone") {
		t.Error("an unchanged validated Zones refuses")
	}
}

func TestNewScope(t *testing.T) {
	s, err := testZones.NewScope([]string{"notes/findings/a/", "inbox/"}, []string{"owner/approved/"})
	if err != nil || CheckWrite(s, "inbox/x.md") != nil || CheckRead(s, "owner/approved/x.md") != nil {
		t.Fatalf("NewScope = %+v, %v", s, err)
	}
	for _, c := range []struct{ w, r []string }{
		{[]string{"owner/approved/"}, nil},
		{[]string{"inbox//x/"}, nil},
		{nil, []string{"../etc/"}},
	} {
		if _, err := testZones.NewScope(c.w, c.r); !errors.Is(err, ErrBadPrefix) {
			t.Errorf("NewScope(%v, %v) = %v, want ErrBadPrefix", c.w, c.r, err)
		}
	}
}

func TestValidateDirPrefix(t *testing.T) {
	for _, p := range []string{"notes/findings/x/", "inbox/"} {
		if err := testZones.ValidateDirPrefix(p); err != nil {
			t.Errorf("ValidateDirPrefix(%q) = %v", p, err)
		}
	}
	for _, p := range []string{"notes/findings/x", "inbox", "owner/x/", "notes//x/", ""} {
		if err := testZones.ValidateDirPrefix(p); !errors.Is(err, ErrBadPrefix) {
			t.Errorf("ValidateDirPrefix(%q) = %v, want ErrBadPrefix", p, err)
		}
	}
}

func TestValidateVerdictPrefix(t *testing.T) {
	for _, p := range []string{"notes/findings/review/", "notes/findings/review-shadow/", "notes/findings/a/b/"} {
		if err := testZones.ValidateVerdictPrefix(p); err != nil {
			t.Errorf("ValidateVerdictPrefix(%q) = %v", p, err)
		}
	}
	for _, p := range []string{"inbox/", "inbox/v/", "notes/", "notes/findings/", "notes/state/x/", "notes/findings/review", "owner/approved/", "notes/findings/x/../../../inbox/"} {
		if err := testZones.ValidateVerdictPrefix(p); !errors.Is(err, ErrBadPrefix) {
			t.Errorf("ValidateVerdictPrefix(%q) = %v, want ErrBadPrefix", p, err)
		}
	}
	// a shared prefix under the findings root is refused both ways round
	z := mustZones(Zones{DeniedRoots: []string{"owner"}, FindingsRoot: "notes/findings/", SharedWrite: []string{"notes/findings/shared/x/"}})
	for _, p := range []string{"notes/findings/shared/", "notes/findings/shared/x/", "notes/findings/shared/x/y/"} {
		if err := z.ValidateVerdictPrefix(p); !errors.Is(err, ErrBadPrefix) {
			t.Errorf("ValidateVerdictPrefix(%q) overlapping a shared prefix = %v, want ErrBadPrefix", p, err)
		}
	}
}

func TestReservedName(t *testing.T) {
	z := mustZones(Zones{AllowNoDeniedRoots: true, ReservedNames: []string{"operator", "Root-Session"}})
	for _, n := range []string{"operator", "operator-review", "Operator", "OPERATOR-x", " operator ", "root-session", "root-session-2"} {
		if !z.ReservedName(n) {
			t.Errorf("%q must be reserved", n)
		}
	}
	for _, n := range []string{"", "watcher", "operators", "my-operator", "operator_ops", "root"} {
		if z.ReservedName(n) {
			t.Errorf("%q must not be reserved", n)
		}
	}
}

func TestZonesValidate(t *testing.T) {
	if _, err := testZones.Validate(); err != nil {
		t.Fatalf("the test zones: %v", err)
	}
	for _, c := range []struct {
		name string
		z    Zones
		want string
	}{
		{"no denied roots", Zones{}, "allow_no_denied_roots"},
		{"nested denied root", Zones{DeniedRoots: []string{"owner/approved"}}, "one top-level directory"},
		{"nested denied root with slash", Zones{DeniedRoots: []string{"owner/approved/"}}, "one top-level directory"},
		{"absolute denied root", Zones{DeniedRoots: []string{"/owner"}}, "plain relative path"},
		{"denied root twice", Zones{DeniedRoots: []string{"owner", "Owner/"}}, "listed twice"},
		{"findings root without slash", Zones{AllowNoDeniedRoots: true, FindingsRoot: "notes/findings"}, "must end in"},
		{"findings root in a denied root", Zones{DeniedRoots: []string{"owner"}, FindingsRoot: "owner/findings/"}, "never writable"},
		{"shared prefix in a denied root", Zones{DeniedRoots: []string{"owner"}, SharedWrite: []string{"owner/inbox/"}}, "never writable"},
		{"unclean shared prefix", Zones{AllowNoDeniedRoots: true, SharedWrite: []string{"inbox//x/"}}, "not a clean path"},
		{"empty reserved name", Zones{AllowNoDeniedRoots: true, ReservedNames: []string{""}}, "plain non-empty name"},
		{"spaced reserved name", Zones{AllowNoDeniedRoots: true, ReservedNames: []string{" ops"}}, "plain non-empty name"},
	} {
		_, err := c.z.Validate()
		if !errors.Is(err, ErrBadPrefix) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Validate = %v, want ErrBadPrefix mentioning %q", c.name, err, c.want)
		}
	}
}
