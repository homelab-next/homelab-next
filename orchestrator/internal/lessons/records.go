// SPDX-License-Identifier: Apache-2.0

package lessons

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
	"golang.org/x/sys/unix"
)

// The register format this package reads is homelab-next's (homelabnext/registers/records.py):
// a register is a directory of record files, <uid>.md each, YAML front matter between "---" lines
// and the long prose fields as "## Heading" sections of the body; what several writers append to
// (reviews, recurrences, lifecycle transitions) is one file per event in <uid>.events/ beside it.
// This package reads what it scores and quotes, applies the transitions (a lesson's current
// status, a runbook's superseded_by), and leaves validation to the register's own tools
// (`hnx registers`): it refuses only what it cannot read, or could misread.

// Bounds on what is read.
const (
	maxRecordBytes = 256 << 10
	maxEventBytes  = 64 << 10
	maxRecords     = 10000
	maxEvents      = 1000 // entries in one record's events directory
)

// uidRe is a canonical UUIDv7, the record's identity and its file name.
var uidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// h2Re is a "## " heading; fenceRe opens or closes fenced code, inside which a heading is text.
var (
	h2Re    = regexp.MustCompile(`^##[ \t]+(.+?)[ \t]*$`)
	fenceRe = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})")
)

// sections maps each body heading this package reads to its field.
var sections = map[string]map[string]string{
	"lessons":  {"Symptom": "symptom", "Preventive control": "preventive_control", "Method": "method"},
	"runbooks": {"Purpose": "purpose"},
}

// record is one record file: its front matter (decoded into the caller's type) and the sections
// this package reads.
type record struct {
	front  *yaml.Node
	fields map[string]string
}

// readRecord parses one record file.
func readRecord(data []byte, kind string) (record, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	rest, ok := strings.CutPrefix(text, "---\n")
	if !ok {
		return record{}, errors.New("must start with a --- front matter block")
	}
	lines := strings.Split(rest, "\n")
	end := -1
	for i, ln := range lines {
		if strings.TrimRight(ln, " \t") == "---" {
			end = i
			break
		}
	}
	if end < 0 {
		return record{}, errors.New("the front matter block is not closed")
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(strings.Join(lines[:end], "\n")), &doc); err != nil {
		return record{}, fmt.Errorf("front matter: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return record{}, errors.New("front matter must be a mapping")
	}
	if err := uniqueKeys(doc.Content[0]); err != nil {
		return record{}, err
	}
	r := record{front: doc.Content[0], fields: map[string]string{}}
	want := sections[kind]
	var cur string
	var body []string
	flush := func() {
		if cur != "" {
			r.fields[cur] = strings.TrimSpace(strings.Join(body, "\n"))
		}
	}
	var fence string
	for _, ln := range lines[end+1:] {
		if m := fenceRe.FindStringSubmatch(ln); m != nil {
			switch {
			case fence == "":
				fence = m[1]
			case m[1][0] == fence[0] && len(m[1]) >= len(fence):
				fence = ""
			}
		} else if fence == "" {
			if m := h2Re.FindStringSubmatch(ln); m != nil {
				flush()
				cur, body = want[m[1]], nil
				if cur != "" {
					if _, dup := r.fields[cur]; dup {
						return record{}, fmt.Errorf("## %s appears twice", m[1])
					}
				}
				continue
			}
		}
		if cur != "" {
			body = append(body, ln)
		}
	}
	flush()
	return r, nil
}

// uniqueKeys refuses a repeated key at any level of the front matter: a reader would see one of
// the two values, the register's validator the other.
func uniqueKeys(n *yaml.Node) error {
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			if k := n.Content[i].Value; seen[k] {
				return fmt.Errorf("front matter: %q appears twice", k)
			} else {
				seen[k] = true
			}
		}
	}
	for _, c := range n.Content {
		if err := uniqueKeys(c); err != nil {
			return err
		}
	}
	return nil
}

// transition is one lifecycle transition event (register_event.schema.json, `transition`).
type transition struct {
	Event string         `yaml:"event"`
	From  string         `yaml:"from"`
	To    string         `yaml:"to"`
	Set   map[string]any `yaml:"set"`
}

// eventNameRe is an event file's name: <UTC stamp>-<event>-<actor>[-<n>].yml.
var eventNameRe = regexp.MustCompile(`^\d{8}T\d{6}Z-([a-z]+)-[a-z0-9-]+\.yml$`)

// transitions reads the transition events of one record, in the order their names sort (their
// time stamps), which is the order the register applies them.
func transitions(dir string) ([]transition, error) {
	fi, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		// a symbolic link would put another record's (or any directory's) events on this one
		return nil, fmt.Errorf("%s: not a directory", filepath.Base(dir))
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(entries) > maxEvents {
		return nil, fmt.Errorf("%s: more than %d events", filepath.Base(dir), maxEvents)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if m := eventNameRe.FindStringSubmatch(e.Name()); m != nil && m[1] == "transition" && e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var out []transition
	for _, name := range names {
		data, err := readBounded(filepath.Join(dir, name), maxEventBytes)
		if err != nil {
			return nil, err
		}
		var t transition
		if err := yaml.Unmarshal(data, &t); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if t.Event != "transition" || t.To == "" {
			return nil, fmt.Errorf("%s: not a transition event", name)
		}
		out = append(out, t)
	}
	return out, nil
}

// readBounded reads a regular file of at most max bytes. It opens the file without following a
// symbolic link and checks the open descriptor, so a file swapped after a check is never read.
func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, max)
	}
	return data, nil
}

// recordFiles lists a register directory's record files (<uid>.md), refusing anything that would
// be read as a record but is not one (a symbolic link, a name that is not a uid).
func recordFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		if !e.Type().IsRegular() {
			return nil, fmt.Errorf("%s: not a regular file", name)
		}
		if !uidRe.MatchString(strings.TrimSuffix(name, ".md")) {
			return nil, fmt.Errorf("%s: a record file is named <uid>.md", name)
		}
		out = append(out, name)
	}
	if len(out) > maxRecords {
		return nil, fmt.Errorf("%s: more than %d records", dir, maxRecords)
	}
	sort.Strings(out)
	return out, nil
}
