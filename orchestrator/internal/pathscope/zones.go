// SPDX-License-Identifier: Apache-2.0

package pathscope

import (
	"fmt"
	"strings"
)

// Zones is a tree's own layout, from configuration (the controller's scope block). Nothing here
// has a default: a zero Zones denies no root, has no findings root (so every verdict directory is
// refused) and reserves no name.
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
}

// Validate refuses a Zones value whose entries are not usable as written: a denied root that is
// not one plain segment, or is listed twice; a findings root that is not a clean directory prefix
// or lies in a denied root; a shared prefix that is not clean or lies in a denied root; an empty
// reserved name, or one with surrounding space or a "/". Every error wraps ErrBadPrefix.
func (z Zones) Validate() error {
	seen := map[string]bool{}
	for _, r := range z.DeniedRoots {
		if err := validatePrefix(r); err != nil {
			return fmt.Errorf("denied root: %w", err)
		}
		if strings.Contains(strings.TrimSuffix(r, "/"), "/") {
			return fmt.Errorf("%w: denied root %q must be one top-level directory", ErrBadPrefix, clipPath(r))
		}
		key := strings.ToLower(strings.TrimSuffix(r, "/"))
		if seen[key] {
			return fmt.Errorf("%w: denied root %q is listed twice", ErrBadPrefix, clipPath(r))
		}
		seen[key] = true
	}
	if z.FindingsRoot != "" {
		if err := z.ValidateDirPrefix(z.FindingsRoot); err != nil {
			return fmt.Errorf("findings root: %w", err)
		}
	}
	for _, s := range z.SharedWrite {
		if err := z.ValidatePrefix(s, true); err != nil {
			return fmt.Errorf("shared write prefix: %w", err)
		}
	}
	for _, n := range z.ReservedNames {
		if n == "" || n != strings.TrimSpace(n) || strings.Contains(n, "/") {
			return fmt.Errorf("%w: reserved name %q must be a plain non-empty name", ErrBadPrefix, clipPath(n))
		}
	}
	return nil
}

// ValidatePrefix refuses a scope prefix that is not a plain, clean relative path (see
// validatePrefix: no absolute or home path, no "..", no hidden segment, no control character, not
// the root, written as it cleans). A writable prefix may also never be, or lie under, one of the
// denied roots, compared case-insensitively after cleaning ("./owner", "Owner/" and
// "owner//x" are all refused for a denied root "owner"). A readable prefix may name a path in a
// denied root, a single file included.
func (z Zones) ValidatePrefix(prefix string, writable bool) error {
	if err := validatePrefix(prefix); err != nil {
		return err
	}
	if writable {
		first, _, _ := strings.Cut(strings.TrimSuffix(prefix, "/"), "/")
		for _, r := range z.DeniedRoots {
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
	if err := z.ValidatePrefix(prefix, true); err != nil {
		return err
	}
	return dirSuffix(prefix)
}

// ValidateVerdictPrefix refuses a verdict directory that is not ValidateDirPrefix-clean, does not
// lie strictly under FindingsRoot, or lies within or covers a SharedWrite prefix. A verdict write
// replaces the file it names, so a verdict directory anywhere else could replace pending work or
// another agent's finding. With no FindingsRoot every verdict directory is refused.
func (z Zones) ValidateVerdictPrefix(prefix string) error {
	if z.FindingsRoot == "" {
		return fmt.Errorf("%w: verdict directory %q: no findings root is configured", ErrBadPrefix, clipPath(prefix))
	}
	if err := z.ValidateDirPrefix(prefix); err != nil {
		return err
	}
	if prefix == z.FindingsRoot || !Within(prefix, []string{z.FindingsRoot}) {
		return fmt.Errorf("%w: verdict directory %q must lie under %s", ErrBadPrefix, clipPath(prefix), z.FindingsRoot)
	}
	for _, s := range z.SharedWrite {
		if Within(prefix, []string{s}) || Within(s, []string{prefix}) {
			return fmt.Errorf("%w: verdict directory %q overlaps %q, which every lane writes", ErrBadPrefix, clipPath(prefix), s)
		}
	}
	return nil
}

// ReservedName reports whether name is one of ReservedNames, or one of them followed by "-" and
// anything, ignoring case and surrounding space.
func (z Zones) ReservedName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, r := range z.ReservedNames {
		r = strings.ToLower(strings.TrimSpace(r))
		if r != "" && (n == r || strings.HasPrefix(n, r+"-")) {
			return true
		}
	}
	return false
}
