// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const extProfileYAML = `id: w-v1
agent_key: w
query_scope:
  tables: [example.events]
  max_rows: 50
`

// querySchemaYAML is a deployment's key, as data (profile_extension_schemas).
const querySchemaYAML = `
type: object
additionalProperties: false
properties:
  tables: {type: array, items: {type: string}}
  max_rows: {type: integer}
`

func mustSchema(t *testing.T, src string) *Schema {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(src), &n); err != nil {
		t.Fatal(err)
	}
	s, err := ParseSchema(&n)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func withExt(exts ...Extension) LoadOptions { return LoadOptions{Zones: testZones, Extensions: exts} }

func loadWith(t *testing.T, body string, opts LoadOptions) (*Registry, error) {
	t.Helper()
	dir := t.TempDir()
	writeProfileFile(t, dir, "w.yaml", body)
	return LoadRegistry(dir, opts)
}

// The loader is strict: an unlisted top-level key, or an unknown field inside a known block,
// fails the load, and the error names the config key that would list it.
func TestLoadRegistry_UnknownKeysAreRejected(t *testing.T) {
	for name, body := range map[string]string{
		"unlisted top-level":    extProfileYAML,
		"typo in a known block": "id: w-v1\nagent_key: w\npath_scope: {writable_prefix: [a/]}\n",
		"typo top-level":        "id: w-v1\nagent_key: w\nallowed_tool: [x]\n",
	} {
		if _, err := loadWith(t, body, plainOptions()); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	_, err := loadWith(t, extProfileYAML, withExt(Extension{Name: "other_scope", Opaque: true}))
	if err == nil || !strings.Contains(err.Error(), "query_scope") || !strings.Contains(err.Error(), "profile_extensions") {
		t.Fatalf("err = %v, want it to name query_scope and profile_extensions", err)
	}
}

// An Extension says how it is checked, once; it may not shadow one of the loader's own keys.
func TestLoadRegistry_ExtensionsAreWellFormed(t *testing.T) {
	s := mustSchema(t, querySchemaYAML)
	for name, exts := range map[string][]Extension{
		"empty name":         {{Name: "", Opaque: true}},
		"neither":            {{Name: "query_scope"}},
		"both":               {{Name: "query_scope", Schema: s, Opaque: true}},
		"listed twice":       {{Name: "query_scope", Opaque: true}, {Name: "query_scope", Opaque: true}},
		"a loader key":       {{Name: "grants", Opaque: true}},
		"another loader key": {{Name: "path_scope", Schema: s}},
	} {
		if _, err := loadWith(t, "id: w-v1\nagent_key: w\n", withExt(exts...)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// A listed key is kept as a node; DecodeExtension decodes it strictly into the deployment's type,
// and Resolve hands out an independent map.
func TestLoadRegistry_ListedExtensionDecodes(t *testing.T) {
	dir := t.TempDir()
	writeProfileFile(t, dir, "w.yaml", extProfileYAML)
	writeProfileFile(t, dir, "plain.yaml", "id: plain-v1\nagent_key: plain\n")
	reg, err := LoadRegistry(dir, withExt(Extension{Name: "query_scope", Schema: mustSchema(t, querySchemaYAML)}))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := reg.Resolve("w")
	var scope struct {
		Tables  []string `yaml:"tables"`
		MaxRows int      `yaml:"max_rows"`
	}
	ok, err := p.DecodeExtension("query_scope", &scope)
	if !ok || err != nil || len(scope.Tables) != 1 || scope.Tables[0] != "example.events" || scope.MaxRows != 50 {
		t.Fatalf("DecodeExtension = %v, %v, %+v", ok, err, scope)
	}
	var strict struct {
		Tables []string `yaml:"tables"`
	}
	if _, err := p.DecodeExtension("query_scope", &strict); err == nil {
		t.Fatal("DecodeExtension must reject a field the target type does not define")
	}
	plain, _ := reg.Resolve("plain")
	if ok, err := plain.DecodeExtension("query_scope", &scope); ok || err != nil {
		t.Fatalf("absent extension = %v, %v; want false, nil", ok, err)
	}
	delete(p.Extensions, "query_scope")
	if again, _ := reg.Resolve("w"); len(again.Extensions) != 1 {
		t.Fatal("Resolve shares the Extensions map with the registry")
	}
}

// A key checked by its schema is accepted and refused where the strict decoder of the same shape
// accepts and refuses it, and stricter where the decoder is lenient (1.5 into an integer); an
// opaque key accepts anything.
func TestExtensionSchemas(t *testing.T) {
	schema := mustSchema(t, querySchemaYAML)
	for name, c := range map[string]struct {
		body string
		ok   bool
	}{
		"valid":      {"query_scope:\n  tables: [example.events]\n  max_rows: 50\n", true},
		"empty map":  {"query_scope: {}\n", true},
		"field typo": {"query_scope: {table: [a]}\n", false},
		"wrong type": {"query_scope: {max_rows: many}\n", false},
		"float":      {"query_scope: {max_rows: 1.5}\n", false},
		"not a map":  {"query_scope: [a]\n", false},
		"item type":  {"query_scope: {tables: [[a]]}\n", false},
		// what is validated is what a tool decodes: no merge key, alias or custom tag
		"merge key":    {"query_scope: {<<: {max_rows: 5}}\n", false},
		"merge typo":   {"query_scope: {tables: [a], <<: {max_row: 5}}\n", false},
		"alias":        {"x_anchor: &a [example.events]\nquery_scope: {tables: *a}\n", false},
		"custom tag":   {"query_scope: !!binary aGVsbG8=\n", false},
		"repeated key": {"query_scope: {max_rows: 1, max_rows: 2}\n", false},
		"deep nesting": {"query_scope: {tables: " + strings.Repeat("[", 40) + strings.Repeat("]", 40) + "}\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			body := "id: w-v1\nagent_key: w\n" + c.body
			exts := []Extension{{Name: "query_scope", Schema: schema}}
			if strings.HasPrefix(c.body, "x_anchor") {
				exts = append(exts, Extension{Name: "x_anchor", Opaque: true})
			}
			if _, err := loadWith(t, body, withExt(exts...)); (err == nil) != c.ok {
				t.Fatalf("schema check err = %v, want ok=%v", err, c.ok)
			}
		})
	}
	if _, err := loadWith(t, "id: w-v1\nagent_key: w\nquery_scope: {anything: [1, {b: c}]}\n", withExt(Extension{Name: "query_scope", Opaque: true})); err != nil {
		t.Fatalf("an opaque key must accept any value: %v", err)
	}
}

// A schema the loader cannot enforce is refused when it is parsed.
func TestParseSchema_RefusesWhatItCannotEnforce(t *testing.T) {
	for _, bad := range []string{
		"type: object\npattern: x\n", "type: tuple\n", "additionalProperties: {type: string}\n",
		"additionalProperties: \"false\"\n", "- a\n", "type: []\n", "enum: []\n", "enum: [{a: b}]\n",
		"required: [a, a]\n", "required: [{a: b}]\n", "title: {a: b}\n",
		"type: object\ntype: array\n",                                          // repeated keyword
		"properties: {a: {type: string}, a: {type: integer}}\n",                // repeated property
		"base: &b {type: string}\nproperties: {a: *b}\n",                       // anchor / alias
		"properties:\n  a: {type: string}\n  b:\n    <<: {type: integer}\n",    // merge key
		"items: {type: string}\nminItems: 1\n",                                 // an unsupported keyword
		strings.Repeat("{items: ", 40) + "{}" + strings.Repeat("}", 40) + "\n", // too deep
	} {
		var n yaml.Node
		if err := yaml.Unmarshal([]byte(bad), &n); err != nil {
			continue // not YAML at all: refused before it is a schema
		}
		if _, err := ParseSchema(&n); err == nil {
			t.Errorf("ParseSchema(%q) accepted a schema it cannot enforce", bad)
		}
	}
	// enum compares type as well as text: 1 is not "1".
	enum := mustSchema(t, "enum: [\"1\", read_only]\n")
	for src, ok := range map[string]bool{`"1"`: true, "read_only": true, "1": false, "true": false} {
		var n yaml.Node
		if err := yaml.Unmarshal([]byte(src), &n); err != nil {
			t.Fatal(err)
		}
		if err := enum.Validate(&n); (err == nil) != ok {
			t.Errorf("enum %s: err = %v, want ok=%v", src, err, ok)
		}
	}
	var req yaml.Node
	if err := yaml.Unmarshal([]byte("tables: []\n"), &req); err != nil {
		t.Fatal(err)
	}
	if err := mustSchema(t, "type: object\nrequired: [max_rows]\n").Validate(&req); err == nil {
		t.Error("a missing required field must fail validation")
	}
	// annotations are allowed; an unquoted date validates as a string
	s := mustSchema(t, "$schema: x\n$id: y\ntitle: t\ndescription: d\n$comment: c\ntype: object\nproperties: {since: {type: string}}\n")
	var dated yaml.Node
	if err := yaml.Unmarshal([]byte("since: 2026-01-01\n"), &dated); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(&dated); err != nil {
		t.Errorf("an unquoted date: %v", err)
	}
}
