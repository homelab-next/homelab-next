// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"

	"go.yaml.in/yaml/v3"
)

// KeyAliases are a site's own old top-level profile keys and the keys they are read as: old ->
// new. Some of the private controller's profile keys cannot be spelt in this repository (the leak
// scan's secret-name rule matches them), so the site supplies the table at runtime from its own
// file, and this code never names them.
type KeyAliases map[string]string

// aliasNameRe is a top-level profile key.
var aliasNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// unaliasable are the keys no alias may target: a profile's identity and its permissions (its
// grants, its tools, what its prompt may read) are read under their own names only. The one
// permission key that may be aliased is path_scope: the private controller's name for it is the
// reason aliases exist, and an aliased scope is checked against the zones as path_scope is.
var unaliasable = []string{"agent_key", "id", "grants", "allowed_tools", "prompt_context"}

// Validate refuses a table that is not a set of plain second names for existing keys: every name
// a plain key; every new name a key the loader defines, never agent_key, id or grants; no old
// name a key the loader defines or the new name of another entry (no chains, no cycles); no two
// old names for one key.
func (a KeyAliases) Validate() error {
	known := reflectProfileKeys()
	targets := map[string]string{}
	for _, old := range a.sorted() {
		target := a[old]
		switch {
		case !aliasNameRe.MatchString(old) || !aliasNameRe.MatchString(target):
			return fmt.Errorf("profile key aliases: %q -> %q: both must be plain key names", clip(old), clip(target))
		case slices.Contains(known, old):
			return fmt.Errorf("profile key aliases: %s is already a profile key", old)
		case !slices.Contains(known, target):
			return fmt.Errorf("profile key aliases: %s -> %s: not a profile key", old, target)
		case slices.Contains(unaliasable, target):
			return fmt.Errorf("profile key aliases: %s -> %s: an identity or a permission is read under its own name only", old, target)
		case a[target] != "":
			return fmt.Errorf("profile key aliases: %s -> %s: %s is aliased itself (no chains)", old, target, target)
		case targets[target] != "":
			return fmt.Errorf("profile key aliases: %s and %s both name %s", targets[target], old, target)
		}
		targets[target] = old
	}
	return nil
}

func (a KeyAliases) sorted() []string {
	out := make([]string, 0, len(a))
	for k := range a {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// apply returns data with every aliased top-level key renamed, and a note per rename; data comes
// back as it is when no alias applies. A profile that sets an old key and its new key is refused.
func (a KeyAliases) apply(data []byte) ([]byte, []string, error) {
	if len(a) == 0 {
		return data, nil, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}
	notes, err := a.rename(&doc)
	if err != nil || len(notes) == 0 {
		return data, nil, err
	}
	out, err := yaml.Marshal(&doc)
	return out, notes, err
}

func (a KeyAliases) rename(doc *yaml.Node) ([]string, error) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil // empty, or not a mapping: the strict decode says what is wrong
	}
	top := doc.Content[0]
	present := map[string]bool{}
	for i := 0; i+1 < len(top.Content); i += 2 {
		present[top.Content[i].Value] = true
	}
	var notes []string
	for i := 0; i+1 < len(top.Content); i += 2 {
		old := top.Content[i].Value
		target, ok := a[old]
		if !ok {
			continue
		}
		if present[target] {
			return nil, fmt.Errorf("%s and %s are both set: they are one setting (keep %s)", old, target, target)
		}
		top.Content[i].Value = target
		notes = append(notes, fmt.Sprintf("read %s as %s (a site alias)", old, target))
	}
	return notes, nil
}

// ParseKeyAliases decodes a site's profile key aliases file: one mapping of old key to new key,
// decoded strictly (a repeated key refused) and validated.
func ParseKeyAliases(data []byte) (KeyAliases, error) {
	var a KeyAliases
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("profile key aliases: %w", err)
	}
	return a, a.Validate()
}

// MigrateDir rewrites every profile file (*.yaml) in dir with each alias of opts.KeyAliases under
// its new name, comments kept, and returns a note per rename; a file with nothing to rename is
// left as it is. It is all or nothing: every file is read as the loader reads it (no symbolic link
// followed, a regular file, bounded), and the whole rewritten directory must load with opts and
// no aliases before any file is written. Each file is then replaced by a new, exclusively
// created temporary file in dir (a random name, never one planted in advance), given the mode of
// the file it replaces (read from the same descriptor), synced and renamed over it, and dir is
// synced; a temporary file is removed on any error.
func MigrateDir(dir string, opts LoadOptions) ([]string, error) {
	aliases := opts.KeyAliases
	if err := aliases.Validate(); err != nil {
		return nil, err
	}
	files, err := readProfileDir(dir)
	if err != nil {
		return nil, err
	}
	var notes []string
	var writes []profileFile
	rewritten := make([]profileFile, 0, len(files))
	for _, f := range files {
		var doc yaml.Node
		if err := yaml.Unmarshal(f.data, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", f.path, err)
		}
		renamed, err := aliases.rename(&doc)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.path, err)
		}
		if len(renamed) == 0 {
			rewritten = append(rewritten, f)
			continue
		}
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(&doc); err != nil {
			return nil, err
		}
		if err := enc.Close(); err != nil {
			return nil, err
		}
		out := profileFile{f.path, buf.Bytes(), f.mode}
		rewritten = append(rewritten, out)
		writes = append(writes, out)
		for _, n := range renamed {
			notes = append(notes, filepath.Base(f.path)+": "+n)
		}
	}
	check := opts
	check.KeyAliases = nil
	if _, err := buildRegistry(rewritten, check); err != nil {
		return nil, fmt.Errorf("the migrated profiles do not load (nothing written): %w", err)
	}
	for _, w := range writes {
		if err := replaceFile(dir, w); err != nil {
			return nil, err
		}
	}
	if len(writes) > 0 {
		if err := syncDir(dir); err != nil {
			return nil, err
		}
	}
	return notes, nil
}

// replaceFile writes w.data to a new temporary file in dir and renames it over w.path.
func replaceFile(dir string, w profileFile) (err error) {
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(w.path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(w.mode); err != nil {
		return err
	}
	if _, err = tmp.Write(w.data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), w.path)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
