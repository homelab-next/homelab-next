// SPDX-License-Identifier: Apache-2.0

package schematest

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Only tests import the validator: it is test support, never part of what the controller runs.
func TestOnlyTestsImportIt(t *testing.T) {
	const self = "github.com/homelab-next/homelab-next/orchestrator/internal/schematest"
	fset := token.NewFileSet()
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == self {
				t.Errorf("%s imports %s", path, self)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Every schema directory loads, and an id schema resolves.
func TestLoad(t *testing.T) {
	v, err := Load("../../../schemas")
	if err != nil {
		t.Fatal(err)
	}
	r, err := v.ValidateStem("agent.job.failed", map[string]any{})
	if err != nil || len(r.Unsupported) > 0 || len(r.Errs) == 0 {
		t.Fatalf("an empty object against agent.job.failed = %+v, %v; want refused", r, err)
	}
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("a directory with no schemas loaded")
	}
}
