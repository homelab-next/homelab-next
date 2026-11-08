// SPDX-License-Identifier: Apache-2.0

// Package pathscope decides whether a relative path falls inside a scope: lists of writable and
// readable prefixes under one shared tree (a store of notes, findings and proposals that agents
// read and write through their tools). It works on path strings only; package safefs makes the
// filesystem object reached be the one the string names.
//
// The rules are generic. What a tree's zones are (which top-level directories are never
// writable, where findings live, which prefixes every lane shares, which identities no agent may
// take) is configuration, given as a Zones value. This package hard-codes no zone name.
package pathscope

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

// ErrDenied wraps every CheckRead and CheckWrite refusal.
var ErrDenied = errors.New("path denied by scope")

// ErrBadPrefix wraps every refusal of a scope prefix or of a Zones value.
var ErrBadPrefix = errors.New("invalid scope prefix")

// Scope is what one caller may write and read. A writable prefix is readable too.
type Scope struct {
	WritablePrefixes []string
	ReadablePrefixes []string
}

// cleanRelPath drops a leading slash and resolves "." and ".." segments. A path that climbs
// further than its own depth cleans to one starting with "..", which no relative prefix matches,
// so the prefix check below needs no separate traversal test: a path that escaped looks, after
// cleaning, like any other path outside the scope.
func cleanRelPath(p string) string {
	return path.Clean(strings.TrimPrefix(p, "/"))
}

// maxEchoedPath bounds a caller-supplied path quoted back in an error, so a huge path does not
// become a huge error on every call.
const maxEchoedPath = 256

// clipPath cuts p to maxEchoedPath bytes on a rune boundary and appends its full length.
func clipPath(p string) string {
	if len(p) <= maxEchoedPath {
		return p
	}
	cut := maxEchoedPath
	for cut > 0 && !utf8.RuneStart(p[cut]) {
		cut--
	}
	return fmt.Sprintf("%s...[%d bytes]", p[:cut], len(p))
}

// scopeEntry returns a scope prefix as hasAnyPrefix matches it: cleaned, so "a//b/" or "a/./b/"
// means the directory it spells. A Scope can be built without ValidatePrefix, so an entry that
// does not plainly name a directory is unusable (ok false): empty or the root (it would match
// everything), absolute, or holding any ".." segment. Cleaning "a/x/../../b/" would give "b", and
// "a/../../c/" would give "../c": entries matching paths the entry never named.
func scopeEntry(prefix string) (clean string, ok bool) {
	trimmed := strings.TrimSuffix(prefix, "/")
	if trimmed == "" || strings.HasPrefix(trimmed, "/") {
		return "", false
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == ".." {
			return "", false
		}
	}
	clean = path.Clean(trimmed)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", false
	}
	return clean, true
}

// hasAnyPrefix reports whether p is one of prefixes or lies under one, segment by segment
// ("a/b" never matches "a/bc").
func hasAnyPrefix(p string, prefixes []string) bool {
	for _, prefix := range prefixes {
		trimmed, ok := scopeEntry(prefix)
		if !ok {
			continue // never match through an entry that does not plainly name a directory
		}
		if p == trimmed || strings.HasPrefix(p, trimmed+"/") {
			return true
		}
	}
	return false
}

// CheckWrite returns nil when p, cleaned, lies under one of scope's writable prefixes and has no
// hidden segment (HasHiddenSegment), and an error wrapping ErrDenied otherwise.
func CheckWrite(scope Scope, p string) error {
	clean := cleanRelPath(p)
	if HasHiddenSegment(clean) {
		return hiddenErr(p, clean)
	}
	if hasAnyPrefix(clean, scope.WritablePrefixes) {
		return nil
	}
	return fmt.Errorf("%w: %q is not under any writable prefix", ErrDenied, clipPath(p))
}

// CheckRead returns nil when p, cleaned, lies under a writable or a readable prefix of scope and
// has no hidden segment, and an error wrapping ErrDenied otherwise. There is no wildcard: what no
// prefix names is denied.
func CheckRead(scope Scope, p string) error {
	clean := cleanRelPath(p)
	if HasHiddenSegment(clean) {
		return hiddenErr(p, clean)
	}
	if hasAnyPrefix(clean, scope.WritablePrefixes) || hasAnyPrefix(clean, scope.ReadablePrefixes) {
		return nil
	}
	return fmt.Errorf("%w: %q is not under any readable or writable prefix", ErrDenied, clipPath(p))
}

// hiddenErr refuses a path that, cleaned, names a hidden file or directory. A prefix can never
// name one (ValidatePrefix refuses it), and a path under a prefix must not reach one either:
// under a code checkout that is the repository's .git or an .env.
func hiddenErr(p, clean string) error {
	return fmt.Errorf("%w: %q names a hidden file or directory (.git, .env, ...)", ErrDenied, clipPath(clean))
}

// Within reports whether prefix (already ValidatePrefix-clean) names the same path as one of
// within, or a path under one: granting prefix gives no more than granting within already does.
func Within(prefix string, within []string) bool {
	return hasAnyPrefix(path.Clean(prefix), within)
}

// HasHiddenSegment reports whether p names a hidden file or directory anywhere along it: a
// segment that starts with "." other than "." itself (".git", ".env", ".."). Scopes never reach
// one: under a code checkout that is the repository's .git (its config and hooks) or an .env.
func HasHiddenSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if strings.HasPrefix(seg, ".") && seg != "." {
			return true
		}
	}
	return false
}

// shadowTokenRe finds the token that marks a shadow-lane path or name: "shadow" between
// separators or at either end (work/findings/watch-shadow/, import_state-shadow.json, shadow/).
var shadowTokenRe = regexp.MustCompile(`(?i)(?:^|[-_/.])shadow(?:$|[-_/.])`)

// ShadowMarked reports whether v carries the shadow-lane token. It is the one definition of "a
// shadow path", shared by the grant lane rules and the servers that check their own paths.
func ShadowMarked(v string) bool { return shadowTokenRe.MatchString(v) }

// validatePrefix refuses a scope prefix that is not a plain relative path: empty or surrounded
// by space; absolute or home-relative; holding a backslash, a NUL, any other control character or
// a line break; holding a ".." segment (even one cleaning would cancel) or a hidden segment
// (HasHiddenSegment); naming the root ("." or "./"); or not clean ("a//b", "a/./b", "./a": the
// prefix must read as path.Clean leaves it, but for one trailing "/"). Zones.ValidatePrefix adds
// a tree's zones to it.
func validatePrefix(prefix string) error {
	if prefix == "" || prefix != strings.TrimSpace(prefix) {
		return fmt.Errorf("%w: %q is empty or has surrounding space", ErrBadPrefix, clipPath(prefix))
	}
	if strings.HasPrefix(prefix, "/") || strings.HasPrefix(prefix, "~") || strings.ContainsAny(prefix, "\\\x00") {
		return fmt.Errorf("%w: %q must be a plain relative path", ErrBadPrefix, clipPath(prefix))
	}
	for _, seg := range strings.Split(prefix, "/") {
		if seg == ".." {
			return fmt.Errorf("%w: %q holds a \"..\" segment", ErrBadPrefix, clipPath(prefix))
		}
	}
	if HasHiddenSegment(prefix) {
		return fmt.Errorf("%w: %q names a hidden file or directory (.git, .env, ...)", ErrBadPrefix, clipPath(prefix))
	}
	for _, r := range prefix {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029 {
			return fmt.Errorf("%w: %q holds a control or line-break character", ErrBadPrefix, clipPath(prefix))
		}
	}
	clean := path.Clean(prefix)
	if clean == "." {
		return fmt.Errorf("%w: %q names the root", ErrBadPrefix, clipPath(prefix))
	}
	// a prefix is compared as written, so it must already be clean: "a//b/x/" and "a/./b/x/"
	// name a/b/x/ to the filesystem but not to a string comparison (a lane check, Within, a
	// lookup by prefix). One trailing "/" is the only spelling difference allowed
	if trimmed := strings.TrimSuffix(prefix, "/"); clean != trimmed {
		return fmt.Errorf("%w: %q is not a clean path (write it as %q)", ErrBadPrefix, clipPath(prefix), clean+strings.Repeat("/", len(prefix)-len(trimmed)))
	}
	return nil
}

// dirSuffix refuses a directory prefix that does not end in "/": the file name is appended to it
// as written.
func dirSuffix(prefix string) error {
	if !strings.HasSuffix(prefix, "/") {
		return fmt.Errorf("%w: %q must end in \"/\" (it names a directory)", ErrBadPrefix, clipPath(prefix))
	}
	return nil
}
