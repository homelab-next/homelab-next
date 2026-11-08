// SPDX-License-Identifier: Apache-2.0

package api

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/homelab-next/homelab-next/orchestrator/internal/errtext"
)

// The API decides on typed values only: no file of it decides on an error's text, or imports
// regexp (package errtext). Error text goes to the log, never into a response.
func TestTheAPIReadsNoErrorText(t *testing.T) {
	got, err := errtext.Check(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		t.Error(f)
	}
}

// The API takes the scheduler's and the pool's behaviour as functions: it imports neither.
func TestTheAPIImportsNoScheduler(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			for _, banned := range []string{"/internal/queue", "/internal/backends", "/internal/runner"} {
				if strings.HasSuffix(p, banned) || strings.Contains(p, banned+"/") {
					t.Errorf("%s imports %s", e.Name(), p)
				}
			}
		}
	}
}
