// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/homelab-next/homelab-next/orchestrator/internal/grants"
)

// SiteRenames are a site's own old configuration key names and the keys they become: old key
// path -> new key path. Some of the private controller's key names cannot be spelt in this
// repository (the leak scan's secret-name rule matches them), so the site that has them supplies
// the table at runtime, from its own (private) file, and this code never names them. The table
// is held strictly (Validate): it can only give an existing key a second name, never invent a
// key, move a key into the scope zones or the API's credentials, or chain renames.
type SiteRenames map[string]string

// keyPathRe is a dotted key path (an old name: one segment) of plain lower-case names.
var keyPathRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}(?:\.[a-z][a-z0-9_]{0,63}){0,3}$`)

// protectedPrefixes are the keys no site rename may target: the scope zones must be written as
// such, and the API's credentials file is never reached through another name.
var protectedPrefixes = []string{"scope", "api_auth"}

// knownKeys are every key path the configuration reads, with "backends.<name>." for each backend.
func knownKeys() map[string]bool {
	out := map[string]bool{}
	for _, k := range allConfigKeys(reflect.TypeFor[Config](), "") {
		out[k] = true
	}
	return out
}

func allConfigKeys(t reflect.Type, at string) []string {
	var out []string
	for f := range t.Fields() {
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "" || name == "-" {
			continue
		}
		out = append(out, at+name)
		ft := f.Type
		for ft.Kind() == reflect.Slice || ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct && ft.PkgPath() == reflect.TypeFor[Config]().PkgPath() {
			out = append(out, allConfigKeys(ft, at+name+".")...)
		}
	}
	return out
}

// Validate refuses a table that is not a set of plain second names for existing keys: every old
// and new name a key path; every new name a key the configuration reads, outside the scope zones
// and the API's credentials; no old name a key the configuration reads, an old name of Renames
// or Dropped, or the new name of another entry (no chains, no cycles); no two old names for one
// new key.
func (r SiteRenames) Validate() error {
	known := knownKeys()
	builtin := map[string]bool{}
	for _, b := range Renames {
		builtin[b.Old], builtin[b.New] = true, true
	}
	for d := range Dropped {
		builtin[d] = true
	}
	targets := map[string]string{}
	for _, old := range r.sorted() {
		target := r[old]
		switch {
		case !keyPathRe.MatchString(old) || strings.Contains(old, ".") || !keyPathRe.MatchString(target):
			return fmt.Errorf("site renames: %q -> %q: the old name is a top-level key, the new one a dotted key path", clip(old), clip(target))
		case known[old] || builtin[old]:
			return fmt.Errorf("site renames: %s is already a key or a built-in rename", old)
		case !known[target]:
			return fmt.Errorf("site renames: %s -> %s: not a key the configuration reads", old, target)
		case strings.HasPrefix(target, "backends.additional."):
			// a key inside a list entry: a top-level old key cannot say which entry it is
			return fmt.Errorf("site renames: %s -> %s: a key of a list entry cannot be a rename's target", old, target)
		case r[target] != "":
			return fmt.Errorf("site renames: %s -> %s: %s is renamed itself (no chains)", old, target, target)
		case targets[target] != "":
			return fmt.Errorf("site renames: %s and %s both name %s", targets[target], old, target)
		}
		for _, p := range protectedPrefixes {
			if target == p || strings.HasPrefix(target, p+".") {
				return fmt.Errorf("site renames: %s -> %s: the %s block is written under its own keys", old, target, p)
			}
		}
		targets[target] = old
	}
	return nil
}

func (r SiteRenames) sorted() []string {
	out := make([]string, 0, len(r))
	for k := range r {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// renames validates the table and returns it as Renames entries.
func (r SiteRenames) renames() ([]Rename, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	out := make([]Rename, 0, len(r))
	for _, old := range r.sorted() {
		out = append(out, Rename{Old: old, New: r[old], Note: "a site rename"})
	}
	return out, nil
}

// ParseSiteRenames decodes a site's renames file: one mapping of old key path to new key path,
// decoded strictly (a repeated key refused) and validated.
func ParseSiteRenames(data []byte) (SiteRenames, error) {
	var r SiteRenames
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("site renames: %w", err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// LoadSiteRenames reads and checks a site's renames file (ParseSiteRenames).
func LoadSiteRenames(path string) (SiteRenames, error) {
	data, err := grants.ReadConfigFile(path, 64<<10)
	if err != nil {
		return nil, fmt.Errorf("site renames: %w", err)
	}
	return ParseSiteRenames(data)
}

// clip bounds a string quoted in an error, never cutting a UTF-8 sequence.
func clip(s string) string {
	const max = 80
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
