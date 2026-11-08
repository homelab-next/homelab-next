// SPDX-License-Identifier: Apache-2.0

package pathscope

import (
	"fmt"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/homelab-next/homelab-next/orchestrator/internal/fuzzseed"
)

// The fuzz targets of this package (ADR-0048 decision 1). Each property is a function of the
// reference it compares with: componentRef is the reference, stringRef the deliberately wrong one
// (it compares strings, not path components), and TestFuzz*PropertyCanFail proves on the seed
// corpus that the property, checked against the wrong one, fails.

// ref decides whether p lies in one of prefixes.
type ref func(prefixes []string, p string) bool

// components returns p cleaned (one leading "/" dropped, as a caller's absolute-looking path is
// read under the tree) as path segments, or ok false when it names the root or climbs out of it.
func components(p string) ([]string, bool) {
	c := path.Clean(strings.TrimPrefix(p, "/"))
	if c == "." || c == ".." || strings.HasPrefix(c, "../") || strings.HasPrefix(c, "/") {
		return nil, false
	}
	return strings.Split(c, "/"), true
}

// componentRef is the reference: an entry that is not absolute and holds no ".." segment names
// the directory path.Clean makes of it, and p lies in it when the entry's segments are the first
// segments of p's.
func componentRef(prefixes []string, p string) bool {
	pc, ok := components(p)
	if !ok {
		return false
	}
	for _, e := range prefixes {
		if strings.HasPrefix(e, "/") || slices.Contains(strings.Split(e, "/"), "..") {
			continue
		}
		ec, ok := components(e)
		if !ok {
			continue
		}
		if len(ec) <= len(pc) && slices.Equal(ec, pc[:len(ec)]) {
			return true
		}
	}
	return false
}

// stringRef is the wrong reference: the raw path starts with the entry's text.
func stringRef(prefixes []string, p string) bool {
	for _, e := range prefixes {
		if e = strings.TrimSuffix(e, "/"); e != "" && strings.HasPrefix(p, e) {
			return true
		}
	}
	return false
}

// canonical reports whether p is written as it cleans, relative and inside the tree: on such a
// path the reference and CheckWrite/CheckRead must agree exactly, not only one way.
func canonical(p string) bool {
	_, ok := components(p)
	return ok && p == path.Clean(p) && !strings.HasPrefix(p, "/")
}

// checkProperty is FuzzCheck's property for scope and p, against r. CheckWrite and CheckRead allow
// p only when r allows it and its cleaned form has no hidden segment, a write allowed implies a
// read allowed, and on a canonical p under a scope whose entries ValidatePrefix accepts, they allow
// exactly what r allows (no hidden segment).
func checkProperty(r ref, scope Scope, p string) error {
	clean := path.Clean(strings.TrimPrefix(p, "/"))
	w, rd := CheckWrite(scope, p) == nil, CheckRead(scope, p) == nil
	both := append(slices.Clone(scope.WritablePrefixes), scope.ReadablePrefixes...)
	if w && !rd {
		return fmt.Errorf("%q is writable and not readable", p)
	}
	if (w || rd) && HasHiddenSegment(clean) {
		return fmt.Errorf("%q (cleans to %q) is allowed and has a hidden segment", p, clean)
	}
	if w && !r(scope.WritablePrefixes, p) {
		return fmt.Errorf("CheckWrite allows %q, the reference does not", p)
	}
	if rd && !r(both, p) {
		return fmt.Errorf("CheckRead allows %q, the reference does not", p)
	}
	if !canonical(p) || HasHiddenSegment(p) {
		return nil
	}
	for _, e := range both {
		if validatePrefix(e) != nil {
			return nil
		}
	}
	if want := r(scope.WritablePrefixes, p); w != want {
		return fmt.Errorf("CheckWrite(%q) allowed = %v, the reference says %v", p, w, want)
	}
	if want := r(both, p); rd != want {
		return fmt.Errorf("CheckRead(%q) allowed = %v, the reference says %v", p, rd, want)
	}
	return nil
}

func nonEmpty(v ...string) []string {
	var out []string
	for _, s := range v {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// checkSeeds are the package's table-test inputs: two writable entries, one readable, a path.
var checkSeeds = [][]any{
	{"notes/findings/pipeline/", "inbox/", "owner/approved/", "notes/findings/pipeline/2026-01-01-0900-pipeline.md"},
	{"notes/findings/pipeline/", "inbox/", "owner/approved/", "/inbox/x.md"},
	{"notes/findings/pipeline/", "inbox/", "owner/approved/", "notes/findings/pipeline/../../../owner/approved/evil.md"},
	{"notes/findings/pipeline/", "inbox/", "owner/approved/", "../../../etc/passwd"},
	{"notes/findings/pipeline", "", "", "notes/findings/pipeline-other/x.md"},
	{"notes/findings/network/", "", "owner/priorities.md", "owner/priorities.md/../instructions.md"},
	{"notes/x/../../owner/", "", "notes/x/../../owner/", "owner/approved/a.md"},
	{"notes/./findings/x/", "notes//findings/y/", "", "notes/findings/x/f.md"},
	{"", "", "", ""},
}

func FuzzCheck(f *testing.F) {
	for _, s := range checkSeeds {
		f.Add(s[0].(string), s[1].(string), s[2].(string), s[3].(string))
	}
	f.Fuzz(func(t *testing.T, w1, w2, r1, p string) {
		if err := checkProperty(componentRef, Scope{WritablePrefixes: nonEmpty(w1, w2), ReadablePrefixes: nonEmpty(r1)}, p); err != nil {
			t.Fatal(err)
		}
	})
}

func checkWith(r ref) func([]any) error {
	return func(a []any) error {
		return checkProperty(r, Scope{WritablePrefixes: nonEmpty(a[0].(string), a[1].(string)), ReadablePrefixes: nonEmpty(a[2].(string))}, a[3].(string))
	}
}

func TestFuzzCheckPropertyCanFail(t *testing.T) {
	fuzzseed.HoldsAndCanFail(t, append(fuzzseed.Corpus(t, "FuzzCheck"), checkSeeds...), checkWith(componentRef), checkWith(stringRef))
}

// escapes reports, by r, whether an accepted writable prefix lets a path into a denied root.
type rootRef func(deniedRoot, prefix string) bool

// componentRoot is the reference: the prefix's first cleaned segment is the denied root, ignoring
// case (as the zone rule compares).
func componentRoot(deniedRoot, prefix string) bool {
	pc, ok := components(prefix)
	dc, dok := components(deniedRoot)
	return ok && dok && len(dc) == 1 && strings.EqualFold(pc[0], dc[0])
}

// stringRoot is the wrong reference: the prefix's text starts with the root's.
func stringRoot(deniedRoot, prefix string) bool {
	d := strings.TrimSuffix(deniedRoot, "/")
	return d != "" && strings.HasPrefix(strings.ToLower(prefix), strings.ToLower(d))
}

// zonesProperty is FuzzZones' property: whatever NewZones, NewScope and the Validate*Prefix
// functions accept is a plain prefix by the reference (clean as written, no "..", no hidden
// segment, not absolute, not the root), a writable one lies in no denied root, a directory one
// ends in "/", a verdict directory lies strictly under the findings root and neither within nor
// over a shared prefix, and a path CheckWrite then allows lies in no denied root either.
func zonesProperty(r rootRef, denied, findings, shared, prefix, p string) error {
	z, err := NewZones(Zones{DeniedRoots: nonEmpty(denied), FindingsRoot: findings, SharedWrite: nonEmpty(shared)})
	if err != nil {
		return nil
	}
	roots := nonEmpty(denied)
	plain := func(what, s string) error {
		c, ok := components(s)
		trimmed := strings.TrimSuffix(s, "/")
		if !ok || strings.HasPrefix(s, "/") || path.Clean(trimmed) != trimmed || slices.Contains(c, "..") || HasHiddenSegment(s) {
			return fmt.Errorf("%s %q is accepted and is not a plain prefix", what, s)
		}
		return nil
	}
	inRoot := func(what, s string) error {
		for _, d := range roots {
			if r(d, s) {
				return fmt.Errorf("%s %q is accepted and lies in the denied root %q", what, s, d)
			}
		}
		return nil
	}
	for _, c := range []struct {
		what, s string
		used    bool
	}{{"findings root", findings, findings != ""}, {"shared prefix", shared, shared != ""}} {
		if !c.used {
			continue
		}
		if err := plain(c.what, c.s); err != nil {
			return err
		}
		if err := inRoot(c.what, c.s); err != nil {
			return err
		}
	}
	vw, vr := z.ValidatePrefix(prefix, true), z.ValidatePrefix(prefix, false)
	if vw == nil && vr != nil {
		return fmt.Errorf("%q is accepted as writable and refused as readable", prefix)
	}
	if vr == nil {
		if err := plain("prefix", prefix); err != nil {
			return err
		}
	}
	if vw == nil {
		if err := inRoot("writable prefix", prefix); err != nil {
			return err
		}
		if s, err := z.NewScope([]string{prefix}, nil); err == nil && CheckWrite(s, p) == nil {
			if err := inRoot("path allowed for writing", path.Clean(strings.TrimPrefix(p, "/"))); err != nil {
				return err
			}
		} else if err != nil {
			return fmt.Errorf("NewScope refuses %q, which ValidatePrefix accepts: %v", prefix, err)
		}
	} else if _, err := z.NewScope([]string{prefix}, nil); err == nil {
		return fmt.Errorf("NewScope accepts %q as writable, which ValidatePrefix refuses", prefix)
	}
	if z.ValidateDirPrefix(prefix) == nil && (vw != nil || !strings.HasSuffix(prefix, "/")) {
		return fmt.Errorf("ValidateDirPrefix accepts %q, which is not a writable directory prefix", prefix)
	}
	if z.ValidateVerdictPrefix(prefix) == nil {
		pc, _ := components(prefix)
		fc, ok := components(findings)
		if !ok || len(pc) <= len(fc) || !slices.Equal(fc, pc[:len(fc)]) {
			return fmt.Errorf("verdict directory %q is accepted and does not lie strictly under %q", prefix, findings)
		}
		if shared != "" && (componentRef([]string{shared}, prefix) || componentRef([]string{prefix}, shared)) {
			return fmt.Errorf("verdict directory %q is accepted and overlaps the shared prefix %q", prefix, shared)
		}
	}
	return nil
}

// zonesSeeds: a denied root, a findings root, a shared prefix, the prefix judged, a path.
var zonesSeeds = [][]any{
	{"owner", "notes/findings/", "inbox/", "notes/findings/a/", "notes/findings/a/x.md"},
	{"owner", "notes/findings/", "inbox/", "Owner/approved/", "owner/approved/x.md"},
	{"owner", "notes/findings/", "inbox/", "./owner/", "owner/x"},
	{"owner", "notes/findings/", "inbox/", "owner//approved/", "owner/approved/x"},
	{"owner", "notes/findings/", "inbox/", "owners/", "owners/x.md"},
	{"owner", "notes/findings/", "inbox/", "notes/findings/", "notes/findings/x.md"},
	{"owner", "notes/findings/", "inbox/", "inbox/verdicts/", "inbox/verdicts/x.md"},
	{"owner", "notes/findings/", "notes/findings/shared/", "notes/findings/", "x"},
	{"owner", "", "", "a/../owner/", "owner/x"},
	{"owner", "notes/findings/", "inbox/", "docs/.env", "docs/.env"},
	{"owner/", "notes//findings/", "inbox/", "notes/findings/a/", "a"},
}

func FuzzZones(f *testing.F) {
	for _, s := range zonesSeeds {
		f.Add(s[0].(string), s[1].(string), s[2].(string), s[3].(string), s[4].(string))
	}
	f.Fuzz(func(t *testing.T, denied, findings, shared, prefix, p string) {
		if err := zonesProperty(componentRoot, denied, findings, shared, prefix, p); err != nil {
			t.Fatal(err)
		}
	})
}

func zonesWith(r rootRef) func([]any) error {
	return func(a []any) error {
		return zonesProperty(r, a[0].(string), a[1].(string), a[2].(string), a[3].(string), a[4].(string))
	}
}

func TestFuzzZonesPropertyCanFail(t *testing.T) {
	fuzzseed.HoldsAndCanFail(t, append(fuzzseed.Corpus(t, "FuzzZones"), zonesSeeds...), zonesWith(componentRoot), zonesWith(stringRoot))
}
