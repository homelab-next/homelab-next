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

// With no denied roots, nothing is refused for its zone: the zones are the configuration's, the
// package has none of its own.
func TestZeroZonesDenyNoRoot(t *testing.T) {
	var z Zones
	for _, p := range []string{"owner/", "decisions/", "anything/x/"} {
		if err := z.ValidatePrefix(p, true); err != nil {
			t.Errorf("zero Zones refused %q: %v", p, err)
		}
	}
	if err := z.ValidateVerdictPrefix("notes/findings/x/"); !errors.Is(err, ErrBadPrefix) {
		t.Errorf("a verdict directory with no findings root configured = %v, want ErrBadPrefix", err)
	}
	if z.ReservedName("operator") {
		t.Error("zero Zones reserve a name")
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
	z := testZones
	z.SharedWrite = []string{"notes/findings/shared/x/"}
	for _, p := range []string{"notes/findings/shared/", "notes/findings/shared/x/", "notes/findings/shared/x/y/"} {
		if err := z.ValidateVerdictPrefix(p); !errors.Is(err, ErrBadPrefix) {
			t.Errorf("ValidateVerdictPrefix(%q) overlapping a shared prefix = %v, want ErrBadPrefix", p, err)
		}
	}
}

func TestReservedName(t *testing.T) {
	z := Zones{ReservedNames: []string{"operator", "Root-Session"}}
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
	if err := testZones.Validate(); err != nil {
		t.Fatalf("the test zones: %v", err)
	}
	if err := (Zones{}).Validate(); err != nil {
		t.Fatalf("zero Zones: %v", err)
	}
	for _, c := range []struct {
		name string
		z    Zones
		want string
	}{
		{"nested denied root", Zones{DeniedRoots: []string{"owner/approved"}}, "one top-level directory"},
		{"absolute denied root", Zones{DeniedRoots: []string{"/owner"}}, "plain relative path"},
		{"denied root twice", Zones{DeniedRoots: []string{"owner", "Owner/"}}, "listed twice"},
		{"findings root without slash", Zones{FindingsRoot: "notes/findings"}, "must end in"},
		{"findings root in a denied root", Zones{DeniedRoots: []string{"owner"}, FindingsRoot: "owner/findings/"}, "never writable"},
		{"shared prefix in a denied root", Zones{DeniedRoots: []string{"owner"}, SharedWrite: []string{"owner/inbox/"}}, "never writable"},
		{"unclean shared prefix", Zones{SharedWrite: []string{"inbox//x/"}}, "not a clean path"},
		{"empty reserved name", Zones{ReservedNames: []string{""}}, "plain non-empty name"},
		{"spaced reserved name", Zones{ReservedNames: []string{" ops"}}, "plain non-empty name"},
	} {
		err := c.z.Validate()
		if !errors.Is(err, ErrBadPrefix) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Validate = %v, want ErrBadPrefix mentioning %q", c.name, err, c.want)
		}
	}
}
