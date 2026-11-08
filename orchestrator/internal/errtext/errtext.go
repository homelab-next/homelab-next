// SPDX-License-Identifier: Apache-2.0

// Package errtext checks Go source for decisions made on text the core must not decide on: an
// error's text (it can quote the model's own output, so a model that prints "connection refused"
// would otherwise pick its own class) and a session's output (a result's Response or Stderr). The
// controller's core decides fallback, retry and a job's failure class from typed values (runner
// classes, sentinel errors). A package's test runs Check over the package's directory and fails on
// any finding.
//
// It is an allowlist. Such text may only be formatted and kept: passed to a sink (fmt's printing
// and Errorf, log's printing, and the functions and methods the caller names in Options.Sinks),
// joined with + into a longer string, assigned to a variable or a field, put in a composite
// literal as a value, or returned. Anything else is a finding: a call outside the sinks (a
// strings, bytes, slices or path function, a local helper, errors.New, a scan), a comparison of
// any kind, a switch, a map key, an index or a slice of it, a range over it. An import of regexp is
// a finding too.
//
// The text is: a call of an Error method with no argument (x.Error()); fmt.Sprint, Sprintf or
// Sprintln of such text or of an identifier named as an error (err, or a name ending in err or
// Err); a field named Response or Stderr; the result of a package-level helper sink given such
// text (a method sink's result, an error or nothing, is not text); a
// conversion, a + or a parenthesis around it; and, within one function, a variable assigned from
// it.
//
// It reads syntax, not types, so it is a floor, not a proof. Not followed: an error's fields read
// after errors.As (var e *url.Error; e.Op == "Get"), text passed through a function's parameter or
// result, text stored in a field and read back, and an error held under a name that does not say
// so. Review covers those; this catches the ordinary spellings.
package errtext

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Finding is one match, as file:line: what.
type Finding struct {
	Pos  token.Position
	What string
}

func (f Finding) String() string { return fmt.Sprintf("%s:%d: %s", f.Pos.Filename, f.Pos.Line, f.What) }

// Options are a package's own sinks, beyond fmt's and log's.
type Options struct {
	// Sinks: "name" is a package-level function of the checked package, ".name" a method of that
	// name on any receiver, "path.Func" a function of the package imported from path. Each sink
	// must only format, bound or keep the text, never decide on it.
	Sinks []string
}

var defaultSinks = []string{
	"fmt.Errorf", "fmt.Sprint", "fmt.Sprintf", "fmt.Sprintln", "fmt.Fprint", "fmt.Fprintf", "fmt.Fprintln",
	"fmt.Print", "fmt.Printf", "fmt.Println",
	"log.Print", "log.Printf", "log.Println", "log.Fatal", "log.Fatalf", "log.Fatalln", "log.Panic", "log.Panicf", "log.Panicln",
}

// Check is CheckWith with no sinks of the package's own.
func Check(dir string) ([]Finding, error) { return CheckWith(dir, Options{}) }

// CheckWith parses the non-test .go files of dir and returns every finding, sorted by position.
func CheckWith(dir string, opts Options) ([]Finding, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var out []Finding
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		out = append(out, CheckFileWith(fset, f, opts)...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pos.Filename != out[j].Pos.Filename {
			return out[i].Pos.Filename < out[j].Pos.Filename
		}
		return out[i].Pos.Offset < out[j].Pos.Offset
	})
	return out, nil
}

type checker struct {
	fset    *token.FileSet
	imports map[string]string // local name -> import path
	sinks   map[string]bool   // "path.Func", ".method", "name"
	tainted map[string]bool   // identifiers of the function being checked
	out     []Finding
}

// CheckFile is CheckFileWith with no sinks of the package's own.
func CheckFile(fset *token.FileSet, f *ast.File) []Finding { return CheckFileWith(fset, f, Options{}) }

// CheckFileWith returns the findings of one parsed file.
func CheckFileWith(fset *token.FileSet, f *ast.File, opts Options) []Finding {
	c := &checker{fset: fset, imports: map[string]string{}, sinks: map[string]bool{}}
	for _, s := range append(append([]string(nil), defaultSinks...), opts.Sinks...) {
		c.sinks[s] = true
	}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if path == "regexp" {
			c.add(imp, "imports regexp")
		}
		local := filepath.Base(path)
		if imp.Name != nil {
			local = imp.Name.Name
		}
		c.imports[local] = path
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		c.tainted = map[string]bool{}
		c.propagate(fd.Body)
		c.walk(fd.Body)
	}
	for _, d := range f.Decls { // package-level var initialisers
		if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.VAR {
			c.tainted = map[string]bool{}
			c.walk(gd)
		}
	}
	return c.out
}

func (c *checker) add(n ast.Node, what string) {
	c.out = append(c.out, Finding{Pos: c.fset.Position(n.Pos()), What: what})
}

// propagate marks, to a fixed point, every identifier of the function assigned from text.
func (c *checker) propagate(body ast.Node) {
	for changed := true; changed; {
		changed = false
		mark := func(lhs ast.Expr) {
			if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" && !c.tainted[id.Name] {
				c.tainted[id.Name] = true
				changed = true
			}
		}
		ast.Inspect(body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				if len(x.Lhs) == len(x.Rhs) {
					for i := range x.Rhs {
						if c.isText(x.Rhs[i]) {
							mark(x.Lhs[i])
						}
					}
				}
			case *ast.ValueSpec:
				if len(x.Names) == len(x.Values) {
					for i := range x.Values {
						if c.isText(x.Values[i]) {
							mark(x.Names[i])
						}
					}
				}
			}
			return true
		})
	}
}

// funcName names a call's function as the sinks spell it, and whether it is a conversion.
func (c *checker) funcName(fun ast.Expr) (name string, conversion bool) {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name, f.Name == "string"
	case *ast.ArrayType:
		id, ok := f.Elt.(*ast.Ident)
		return "", ok && f.Len == nil && (id.Name == "byte" || id.Name == "rune")
	case *ast.SelectorExpr:
		if id, ok := f.X.(*ast.Ident); ok {
			if path, imported := c.imports[id.Name]; imported {
				return path + "." + f.Sel.Name, false
			}
		}
		return "." + f.Sel.Name, false
	case *ast.ParenExpr:
		return c.funcName(f.X)
	}
	return "", false
}

func errorNamed(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	if !ok {
		return false
	}
	return id.Name == "err" || strings.HasSuffix(id.Name, "err") || strings.HasSuffix(id.Name, "Err")
}

// isText reports whether e is text the core must not decide on.
func (c *checker) isText(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return c.isText(x.X)
	case *ast.Ident:
		return c.tainted[x.Name]
	case *ast.SelectorExpr:
		return x.Sel.Name == "Response" || x.Sel.Name == "Stderr"
	case *ast.BinaryExpr:
		return x.Op == token.ADD && (c.isText(x.X) || c.isText(x.Y))
	case *ast.CallExpr:
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" && len(x.Args) == 0 {
			return true
		}
		name, conversion := c.funcName(x.Fun)
		if conversion {
			return len(x.Args) == 1 && c.isText(x.Args[0])
		}
		sprint := name == "fmt.Sprint" || name == "fmt.Sprintf" || name == "fmt.Sprintln"
		// a sink's result is text again only for fmt's Sprint family and the package's own
		// helpers (a bounded excerpt, say); a method sink's result (an error, nothing) is not
		localHelper := c.sinks[name] && !strings.Contains(name, ".")
		if !sprint && !localHelper {
			return false
		}
		for _, a := range x.Args {
			if c.isText(a) || (sprint && errorNamed(a)) {
				return true
			}
		}
	}
	return false
}

// walk reports every use of text outside the allowed contexts.
func (c *checker) walk(root ast.Node) {
	var stack []ast.Node
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if e, ok := n.(ast.Expr); ok && len(stack) > 0 && c.isText(e) {
			if what := c.misuse(e, stack[len(stack)-1]); what != "" {
				c.add(e, what)
			}
		}
		stack = append(stack, n)
		return true
	})
}

// misuse says how parent uses the text e, or "" when it only formats or keeps it.
func (c *checker) misuse(e ast.Expr, parent ast.Node) string {
	switch p := parent.(type) {
	case *ast.ParenExpr:
		return "" // judged as the parenthesis
	case *ast.BinaryExpr:
		if p.Op == token.ADD {
			return "" // judged as the longer string
		}
		return "text compared (" + p.Op.String() + ")"
	case *ast.CallExpr:
		if p.Fun == e {
			return ""
		}
		name, conversion := c.funcName(p.Fun)
		if conversion || c.sinks[name] {
			return ""
		}
		if name == "" {
			name = "a function value"
		}
		return "text passed to " + strings.TrimPrefix(name, ".")
	case *ast.AssignStmt:
		for _, l := range p.Lhs {
			if l == e {
				return ""
			}
		}
		if p.Tok == token.ASSIGN || p.Tok == token.DEFINE || p.Tok == token.ADD_ASSIGN {
			return ""
		}
		return "text used in " + p.Tok.String()
	case *ast.ValueSpec, *ast.ReturnStmt, *ast.CompositeLit, *ast.ExprStmt:
		return ""
	case *ast.KeyValueExpr:
		if p.Value == e {
			return ""
		}
		return "text used as a key"
	case *ast.IndexExpr:
		if p.Index == e {
			return "text used as a key"
		}
		return "text indexed"
	case *ast.SliceExpr:
		return "text sliced"
	case *ast.SwitchStmt:
		return "a switch on text"
	case *ast.CaseClause:
		return "text in a case"
	case *ast.RangeStmt:
		return "a range over text"
	case *ast.SelectorExpr:
		return "" // a method on the text's holder (x.Response is the text, x is not)
	}
	return "text used outside formatting"
}
