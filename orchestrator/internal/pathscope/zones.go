// SPDX-License-Identifier: Apache-2.0

package pathscope

import (
	"fmt"
	"slices"
	"strings"
)

// Zones is a tree's own layout, from configuration (the controller's scope block). Nothing here
// has a default. A Zones is used only once validated: NewZones (or Validate) returns the copy
// whose methods work, and every method of a Zones that was not validated refuses (ReservedName
// reports every name reserved). A Zones with no denied root is refused unless AllowNoDeniedRoots
// says so explicitly, so a missing scope block cannot silently make every root writable.
//
// A validated Zones cannot be changed afterwards: it keeps a private copy of what it validated
// and decides on that copy alone. Changing one of its exported fields (or an element of one of
// its lists) does not change a decision; it makes the value refuse everything, as an unvalidated
// one does, until it is validated again. A change is never applied unchecked, and never ignored
// silently.
type Zones struct {
	// DeniedRoots are top-level directories no writable prefix may name or lie under, compared
	// case-insensitively: the zone where an operator's decisions live, for instance, which an
	// agent able to write could use to approve itself. Each is one plain path segment.
	DeniedRoots []string `json:"denied_roots" yaml:"denied_roots"`
	// FindingsRoot is the directory every verdict directory lies strictly under (it ends in
	// "/"). Empty means verdict directories are not in use.
	FindingsRoot string `json:"findings_root" yaml:"findings_root"`
	// SharedWrite are the writable prefixes every lane writes by design (where pending work
	// waits for review). A verdict directory may neither lie within nor cover one, because a
	// verdict write replaces the file it names.
	SharedWrite []string `json:"shared_write" yaml:"shared_write"`
	// ReservedNames are identities no agent may run under: a name equal to an entry, or the
	// entry followed by "-" and anything, compared case-insensitively after trimming space
	// (an entry "ops" reserves "ops" and "ops-review", not "opsy" or "my-ops"). A tree whose
	// tooling trusts some identities (an operator's own sessions, say) lists them here.
	ReservedNames []string `json:"reserved_names" yaml:"reserved_names"`
	// AllowNoDeniedRoots accepts an empty DeniedRoots: a tree where every top-level directory
	// may be granted for writing. It must be set on purpose.
	AllowNoDeniedRoots bool `json:"allow_no_denied_roots" yaml:"allow_no_denied_roots"`

	// sealed is what Validate checked, owned by this value and its copies and never changed.
	sealed *zoneSet
}

// zoneSet is a validated Zones' own copy of its configuration.
type zoneSet struct {
	deniedRoots, sharedWrite, reservedNames []string
	findingsRoot                            string
	allowNoDeniedRoots                      bool
}

// set returns the sealed copy while the exported fields still equal it; nil otherwise (never
// validated, or changed since).
func (z Zones) set() *zoneSet {
	v := z.sealed
	if v == nil || z.FindingsRoot != v.findingsRoot || z.AllowNoDeniedRoots != v.allowNoDeniedRoots ||
		!slices.Equal(z.DeniedRoots, v.deniedRoots) || !slices.Equal(z.SharedWrite, v.sharedWrite) ||
		!slices.Equal(z.ReservedNames, v.reservedNames) {
		return nil
	}
	return v
}

// errNotValidated is what a method of a Zones that did not come from NewZones, or was changed
// after it, returns.
var errNotValidated = fmt.Errorf("%w: the scope zones were not validated, or were changed after (use NewZones)", ErrBadPrefix)

// NewZones validates z and returns the copy whose methods work.
func NewZones(z Zones) (Zones, error) {
	return z.Validate()
}

// Validated reports whether z came from NewZones (or Validate) and is unchanged since: whether its
// methods decide anything. A package that keeps a Zones refuses one that is not.
func (z Zones) Validated() bool { return z.set() != nil }

// NewScope returns the Scope of these prefixes, each checked with ValidatePrefix (writable ones
// against the denied roots).
func (z Zones) NewScope(writable, readable []string) (Scope, error) {
	for _, p := range writable {
		if err := z.ValidatePrefix(p, true); err != nil {
			return Scope{}, err
		}
	}
	for _, p := range readable {
		if err := z.ValidatePrefix(p, false); err != nil {
			return Scope{}, err
		}
	}
	return Scope{WritablePrefixes: append([]string(nil), writable...), ReadablePrefixes: append([]string(nil), readable...)}, nil
}

// Validate refuses a Zones value whose entries are not usable as written: no denied root without
// AllowNoDeniedRoots; a denied root that is not one plain segment, or is listed twice; a findings
// root that is not a clean directory prefix or lies in a denied root; a shared prefix that is not
// clean or lies in a denied root; an empty reserved name, or one with surrounding space or a "/".
// Every error wraps ErrBadPrefix. On success it returns the validated copy (as NewZones does).
func (z Zones) Validate() (Zones, error) {
	z.sealed = nil
	// the validated copy owns its lists: a caller changing its own slices later changes nothing
	z.DeniedRoots = slices.Clone(z.DeniedRoots)
	z.SharedWrite = slices.Clone(z.SharedWrite)
	z.ReservedNames = slices.Clone(z.ReservedNames)
	v := &zoneSet{
		deniedRoots: slices.Clone(z.DeniedRoots), sharedWrite: slices.Clone(z.SharedWrite),
		reservedNames: slices.Clone(z.ReservedNames), findingsRoot: z.FindingsRoot, allowNoDeniedRoots: z.AllowNoDeniedRoots,
	}
	if len(z.DeniedRoots) == 0 && !z.AllowNoDeniedRoots {
		return Zones{}, fmt.Errorf("%w: no denied roots: list the zones no writable prefix may name, or set allow_no_denied_roots", ErrBadPrefix)
	}
	seen := map[string]bool{}
	for _, r := range z.DeniedRoots {
		if err := validatePrefix(r); err != nil {
			return Zones{}, fmt.Errorf("denied root: %w", err)
		}
		if strings.Contains(strings.TrimSuffix(r, "/"), "/") {
			return Zones{}, fmt.Errorf("%w: denied root %q must be one top-level directory", ErrBadPrefix, clipPath(r))
		}
		key := strings.ToLower(strings.TrimSuffix(r, "/"))
		if seen[key] {
			return Zones{}, fmt.Errorf("%w: denied root %q is listed twice", ErrBadPrefix, clipPath(r))
		}
		seen[key] = true
	}
	if z.FindingsRoot != "" {
		if err := v.dirPrefix(z.FindingsRoot); err != nil {
			return Zones{}, fmt.Errorf("findings root: %w", err)
		}
	}
	for _, s := range z.SharedWrite {
		if err := v.prefix(s, true); err != nil {
			return Zones{}, fmt.Errorf("shared write prefix: %w", err)
		}
	}
	for _, n := range z.ReservedNames {
		if n == "" || n != strings.TrimSpace(n) || strings.Contains(n, "/") {
			return Zones{}, fmt.Errorf("%w: reserved name %q must be a plain non-empty name", ErrBadPrefix, clipPath(n))
		}
	}
	z.sealed = v
	return z, nil
}

// ValidatePrefix refuses a scope prefix that is not a plain, clean relative path (see
// validatePrefix: no absolute or home path, no "..", no hidden segment, no control character, not
// the root, written as it cleans). A writable prefix may also never be, or lie under, one of the
// denied roots, compared case-insensitively after cleaning ("./owner", "Owner/" and
// "owner//x" are all refused for a denied root "owner"). A readable prefix may name a path in a
// denied root, a single file included.
func (z Zones) ValidatePrefix(prefix string, writable bool) error {
	v := z.set()
	if v == nil {
		return errNotValidated
	}
	return v.prefix(prefix, writable)
}

func (z *zoneSet) prefix(prefix string, writable bool) error {
	if err := validatePrefix(prefix); err != nil {
		return err
	}
	if writable {
		first, _, _ := strings.Cut(strings.TrimSuffix(prefix, "/"), "/")
		for _, r := range z.deniedRoots {
			if strings.EqualFold(first, strings.TrimSuffix(r, "/")) {
				return fmt.Errorf("%w: %q is in the %s/ zone, which is never writable", ErrBadPrefix, clipPath(prefix), strings.TrimSuffix(r, "/"))
			}
		}
	}
	return nil
}

// ValidateDirPrefix is ValidatePrefix(prefix, true) for a prefix naming the directory a server
// writes its own files into (a findings or a verdict directory). It must also end in "/", because
// the file name is appended to it as written.
func (z Zones) ValidateDirPrefix(prefix string) error {
	v := z.set()
	if v == nil {
		return errNotValidated
	}
	return v.dirPrefix(prefix)
}

func (z *zoneSet) dirPrefix(prefix string) error {
	if err := z.prefix(prefix, true); err != nil {
		return err
	}
	return dirSuffix(prefix)
}

// ValidateVerdictPrefix refuses a verdict directory that is not ValidateDirPrefix-clean, does not
// lie strictly under FindingsRoot, or lies within or covers a SharedWrite prefix. A verdict write
// replaces the file it names, so a verdict directory anywhere else could replace pending work or
// another agent's finding. With no FindingsRoot every verdict directory is refused.
func (z Zones) ValidateVerdictPrefix(prefix string) error {
	v := z.set()
	if v == nil {
		return errNotValidated
	}
	if v.findingsRoot == "" {
		return fmt.Errorf("%w: verdict directory %q: no findings root is configured", ErrBadPrefix, clipPath(prefix))
	}
	if err := v.dirPrefix(prefix); err != nil {
		return err
	}
	if prefix == v.findingsRoot || !Within(prefix, []string{v.findingsRoot}) {
		return fmt.Errorf("%w: verdict directory %q must lie under %s", ErrBadPrefix, clipPath(prefix), v.findingsRoot)
	}
	for _, s := range v.sharedWrite {
		if Within(prefix, []string{s}) || Within(s, []string{prefix}) {
			return fmt.Errorf("%w: verdict directory %q overlaps %q, which every lane writes", ErrBadPrefix, clipPath(prefix), s)
		}
	}
	return nil
}

// ReservedName reports whether name is one of ReservedNames, or one of them followed by "-" and
// anything, ignoring case and surrounding space. Every name is reserved on a Zones that was not
// validated, or was changed after.
func (z Zones) ReservedName(name string) bool {
	v := z.set()
	if v == nil {
		return true
	}
	n := strings.ToLower(strings.TrimSpace(name))
	for _, r := range v.reservedNames {
		r = strings.ToLower(strings.TrimSpace(r))
		if r != "" && (n == r || strings.HasPrefix(n, r+"-")) {
			return true
		}
	}
	return false
}
