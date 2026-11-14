// SPDX-License-Identifier: Apache-2.0

package errtext

import (
	"bufio"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func findings(t *testing.T, src string, opts Options) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, fd := range CheckFileWith(fset, f, opts) {
		out = append(out, fd.What)
	}
	return out
}

// The review's probe cases (testdata/probe/c.go): every one is found but case 6, an error's field
// read after errors.As, which a syntax check cannot tell from any other field (documented).
func TestCheckFindsTheProbeCases(t *testing.T) {
	path := filepath.Join("testdata", "probe", "c.go")
	got, err := Check(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	// each case's statement ends on the line carrying its "// N" comment
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	caseRE := regexp.MustCompile(`// (\d+) `)
	type mark struct{ line, n int }
	var marks []mark
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		if m := caseRE.FindStringSubmatch(sc.Text()); m != nil {
			n, _ := strconv.Atoi(m[1])
			marks = append(marks, mark{line, n})
		}
	}
	found := map[int]bool{}
	for _, fd := range got {
		i := sort.Search(len(marks), func(i int) bool { return marks[i].line >= fd.Pos.Line })
		if i == len(marks) {
			t.Errorf("a finding outside every case: %s", fd)
			continue
		}
		found[marks[i].n] = true
	}
	for n := 1; n <= 15; n++ {
		if want := n != 6; found[n] != want {
			t.Errorf("case %d: found %v, want %v", n, found[n], want)
		}
	}
}

// Every ordinary spelling of a decision on text is found, with what it is.
func TestCheckSaysWhatEachMisuseIs(t *testing.T) {
	src := `package x
import (
	"bytes"
	re "regexp"
	"strings"
)
var _ = re.MustCompile
type R struct{ Response, Stderr string }
func f(err error, r R, m map[string]int) {
	_ = bytes.Contains([]byte(err.Error()), nil)
	_ = err.Error() < "m"
	_ = m[err.Error()]
	_ = err.Error()[0]
	_ = err.Error()[:3]
	switch err.Error() {
	case "x":
	}
	switch {
	case r.Stderr == "x":
	}
	for range r.Response {
	}
	_ = map[string]bool{err.Error(): true}
	_ = strings.Contains(r.Response+"!", "x")
}`
	want := []string{
		"imports regexp",
		"text passed to bytes.Contains",
		"text compared (<)",
		"text used as a key",
		"text indexed",
		"text sliced",
		"a switch on text",
		"text compared (==)",
		"a range over text",
		"text used as a key",
		"text passed to strings.Contains",
	}
	if got := findings(t, src, Options{}); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// Formatting and keeping text is allowed: the fmt and log sinks, the caller's own sinks (whose
// result is text again), +, assignment, a composite literal's value, a return.
func TestCheckLeavesTextThatIsOnlyFormattedAndKept(t *testing.T) {
	src := `package x
import (
	"errors"
	"fmt"
	"log"
)
type R struct{ Response, Detail string }
type P struct{}
func (P) logf(string, ...any) {}
func headSnippet(s string, n int) string { return s }
var errX = errors.New("x")
func f(p P, err error, r R) (string, error) {
	text := err.Error()
	reason := "last attempt: " + headSnippet(text, 400)
	reason += "; " + fmt.Sprintf("%v", err)
	p.logf("failed: %s", headSnippet(err.Error(), 200))
	log.Printf("failed: %v", err)
	out := R{Detail: text, Response: r.Response}
	out.Detail = reason
	_ = out
	if errors.Is(err, errX) {
		return reason, fmt.Errorf("wrapped (%s): %w", text, err)
	}
	return string(err.Error()), nil
}`
	if got := findings(t, src, Options{Sinks: []string{"headSnippet", ".logf"}}); len(got) != 0 {
		t.Errorf("findings = %q", got)
	}
	// the same file without the caller's sinks: both uses are findings
	got := findings(t, src, Options{})
	if len(got) != 2 || got[0] != "text passed to headSnippet" || got[1] != "text passed to headSnippet" {
		t.Errorf("without sinks: %q", got)
	}
}

// A variable assigned from text is text, through any number of steps, within its function.
func TestCheckFollowsVariablesWithinAFunction(t *testing.T) {
	src := `package x
import "strings"
func f(err error) bool {
	a := err.Error()
	b := "x" + a
	var c = b
	return strings.HasPrefix(c, "x")
}
func g(c string) bool { return strings.HasPrefix(c, "x") }`
	if got := findings(t, src, Options{}); fmt.Sprint(got) != "[text passed to strings.HasPrefix]" {
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
