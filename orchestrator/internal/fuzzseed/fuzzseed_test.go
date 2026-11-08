// SPDX-License-Identifier: Apache-2.0

package fuzzseed

import (
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestCorpusReadsGoTestsOwnFormat(t *testing.T) {
	got := Corpus(t, "FuzzSample")
	want := [][]any{{"a\x00\"b", []byte("\xff"), true, -3, uint(7), byte('x')}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Corpus = %#v, want %#v", got, want)
	}
}

func TestParseRefusesWhatItCannotRead(t *testing.T) {
	for _, data := range []string{
		"",
		"string(\"a\")\n",                     // no header
		header + "\n",                         // no value
		header + "\nfloat64(1.5)\n",           // a type no target takes
		header + "\nstring(\"unterminated)\n", // a bad literal
		header + "\nstring\"a\"\n",            // not a conversion
		header + "\nbyte('ab')\n",             // not one byte
	} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("Parse(%q) accepted", data)
		}
	}
}

// recorder is a testing.TB that keeps its failures instead of failing the test.
type recorder struct {
	testing.TB
	failed bool
}

func (r *recorder) Helper()               {}
func (r *recorder) Errorf(string, ...any) { r.failed = true }
func (r *recorder) Fatal(...any)          { r.failed = true }

func TestHoldsAndCanFail(t *testing.T) {
	seeds := [][]any{{1}, {2}}
	pass := func([]any) error { return nil }
	fail := func([]any) error { return errors.New("violated") }
	failOnTwo := func(a []any) error {
		if a[0] == 2 {
			return errors.New("violated")
		}
		return nil
	}
	for _, c := range []struct {
		name         string
		right, wrong func([]any) error
		wantFailed   bool
	}{
		{"holds and a seed catches the wrong reference", pass, failOnTwo, false},
		{"the wrong reference is never caught", pass, pass, true},
		{"the property fails against the right reference", failOnTwo, fail, true},
	} {
		r := &recorder{TB: t}
		HoldsAndCanFail(r, seeds, c.right, c.wrong)
		if r.failed != c.wantFailed {
			t.Errorf("%s: failed = %v, want %v", c.name, r.failed, c.wantFailed)
		}
	}
}

// Only _test.go files import this package, so a helper that imports testing never reaches a
// binary.
func TestOnlyTestFilesImportThisPackage(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(string(mod), "\n")
	self := strings.TrimSpace(strings.TrimPrefix(first, "module ")) + "/internal/fuzzseed"
	fset := token.NewFileSet()
	files := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) && p != root {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		files++
		for _, imp := range f.Imports {
			if path, _ := strconv.Unquote(imp.Path.Value); path == self {
				t.Errorf("%s imports %s, which only tests may import", p, self)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 20 {
		t.Fatalf("read only %d non-test Go files under %s", files, root)
	}
}
