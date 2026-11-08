// SPDX-License-Identifier: Apache-2.0

package errtext

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func findings(t *testing.T, src string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, fd := range CheckFile(fset, f) {
		out = append(out, fd.What)
	}
	return out
}

// Every ordinary spelling of a decision on an error's text is found.
func TestCheckFindsEveryOrdinarySpelling(t *testing.T) {
	src := `package x
import (
	"bytes"
	"fmt"
	re "regexp"
	str "strings"
)
var _ = re.MustCompile
func f(err error) bool {
	if str.Contains(err.Error(), "refused") { return true }
	if str.HasPrefix(string((err).Error()), "x") { return true }
	if bytes.Contains([]byte(err.Error()), nil) { return true }
	if err.Error() == "eof" || "eof" != err.Error() { return true }
	switch err.Error() { case "x": return true }
	if err.Error()[0] == 'x' { return true }
	if err.Error()[:3] == "abc" { return true }
	return str.Contains(fmt.Sprint(err), "timed out")
}`
	got := findings(t, src)
	want := []string{
		"imports regexp",
		"an error's text passed to str.Contains",
		"an error's text passed to str.HasPrefix",
		"an error's text passed to bytes.Contains",
		"an error's text compared", "an error's text compared",
		"a switch on an error's text",
		"an error's text indexed",
		"an error's text sliced",
		"a formatted value passed to str.Contains",
	}
	for _, w := range want {
		i := indexOf(got, w)
		if i < 0 {
			t.Errorf("not found: %q (findings %q)", w, got)
			continue
		}
		got = append(got[:i], got[i+1:]...)
	}
	if len(got) != 0 {
		t.Errorf("unexpected findings: %q", got)
	}
}

// Keeping, logging and quoting an error's text are not decisions on it.
func TestCheckLeavesTextThatIsOnlyKept(t *testing.T) {
	src := `package x
import (
	"errors"
	"fmt"
	"strings"
)
var errX = errors.New("x")
func f(err error) (string, bool) {
	reason := "last attempt: " + err.Error()
	_ = fmt.Errorf("wrapped: %w", err)
	_ = strings.TrimSuffix("a.json", ".json")
	return reason, errors.Is(err, errX)
}`
	if got := findings(t, src); len(got) != 0 {
		t.Errorf("findings = %q", got)
	}
}

func TestCheckReadsADirectorysNonTestFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.go", "package x\nimport \"regexp\"\nvar _ = regexp.MustCompile\n")
	write("a_test.go", "package x\nimport \"regexp\"\nvar _ = regexp.MustCompile\n")
	got, err := Check(dir)
	if err != nil || len(got) != 1 || !strings.HasSuffix(got[0].Pos.Filename, "a.go") || got[0].String() == "" {
		t.Fatalf("findings = %v, %v", got, err)
	}
}

func indexOf(xs []string, s string) int {
	for i, x := range xs {
		if x == s {
			return i
		}
	}
	return -1
}
