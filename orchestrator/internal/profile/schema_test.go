// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/homelab-next/homelab-next/orchestrator/internal/grants"
)

// schemaRoot is schemas/platform, read in place.
var schemaRoot = filepath.Join("..", "..", "..", "schemas", "platform")

type jsonSchema struct {
	Properties map[string]*jsonSchema `json:"properties"`
	Items      *jsonSchema            `json:"items"`
	Ref        string                 `json:"$ref"`
	Defs       map[string]*jsonSchema `json:"$defs"`
}

func loadProfileSchema(t *testing.T) *jsonSchema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(schemaRoot, "orchestrator_profile.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s jsonSchema
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

func sortedKeys(m map[string]*jsonSchema) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sorted(list []string) []string {
	out := slices.Clone(list)
	sort.Strings(out)
	return out
}

// TestTheSchemaNamesTheLoadersKeys: schemas/platform/orchestrator_profile.schema.json documents
// what this loader reads, at every level, so neither can gain or lose a key alone.
func TestTheSchemaNamesTheLoadersKeys(t *testing.T) {
	s := loadProfileSchema(t)
	for _, c := range []struct {
		at     string
		schema *jsonSchema
		typ    reflect.Type
	}{
		{"(top)", s, reflect.TypeFor[Profile]()},
		{"path_scope", s.Properties["path_scope"], reflect.TypeFor[PathScope]()},
		{"toolsets", s.Properties["toolsets"], reflect.TypeFor[Toolsets]()},
		{"prompt_context", s.Properties["prompt_context"], reflect.TypeFor[PromptContext]()},
		{"backend_affinity", s.Properties["backend_affinity"], reflect.TypeFor[BackendAffinity]()},
		{"grants", s.Properties["grants"], reflect.TypeFor[grants.Set]()},
		{"grant", s.Defs["grant"], reflect.TypeFor[grants.Grant]()},
	} {
		if c.schema == nil {
			t.Errorf("%s: not in the schema", c.at)
			continue
		}
		if got, want := sortedKeys(c.schema.Properties), sorted(yamlKeys(c.typ)); !slices.Equal(got, want) {
			t.Errorf("%s: the schema names %v, the loader reads %v", c.at, got, want)
		}
	}
}

// exampleOptions is what the schema's examples need from a controller config.
func exampleOptions() LoadOptions {
	o := plainOptions()
	o.StateFiles = []string{"/srv/notes/state.json"}
	o.FactsCommands = map[string]FactsCommand{"example": {Argv: []string{"/usr/local/bin/facts"}}}
	return o
}

// TestTheSchemasInstancesHaveTheLoadersVerdict: every example loads and every negative is refused
// (each negative is one the loader refuses too, so the schema never promises what the loader
// would not hold).
func TestTheSchemasInstancesHaveTheLoadersVerdict(t *testing.T) {
	for dir, ok := range map[string]bool{"examples": true, "negative": false} {
		files, err := filepath.Glob(filepath.Join(schemaRoot, dir, "orchestrator_profile.*"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: no orchestrator_profile instance (%v)", dir, err)
		}
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			pdir := t.TempDir()
			writeProfileFile(t, pdir, "p.yaml", string(data)) // JSON is YAML
			_, err = LoadRegistry(pdir, exampleOptions())
			if (err == nil) != ok {
				t.Errorf("%s: loader err = %v, want ok=%v", strings.TrimPrefix(f, schemaRoot), err, ok)
			}
		}
	}
}
