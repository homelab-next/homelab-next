// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/homelab-next/homelab-next/orchestrator/internal/errtext"
)

// The pool decides on classes, hints, the answer check and its own sentinels: no file of it matches
// an error's text or imports regexp (package errtext). The scrape package it reads metrics with is
// held to the same.
func TestTheCoreReadsNoErrorText(t *testing.T) {
	for _, dir := range []string{".", "../scrape"} {
		got, err := errtext.Check(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range got {
			t.Errorf("%s: %s", dir, f)
		}
	}
}

// The pool reaches a runner only through the seam: it imports no runner implementation and nothing
// that runs a process.
func TestThePoolImportsNoRunnerImplementation(t *testing.T) {
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
			path, _ := strconv.Unquote(imp.Path.Value)
			if path == "os/exec" || (path == "syscall" && e.Name() != "health.go") || strings.HasPrefix(path, "github.com/homelab-next/homelab-next/orchestrator/internal/runner/") {
				t.Errorf("%s imports %s", e.Name(), path)
			}
		}
	}
}
