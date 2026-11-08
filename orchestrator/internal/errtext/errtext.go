// SPDX-License-Identifier: Apache-2.0

// Package errtext checks Go source for decisions made on an error's text. The controller's core
// decides fallback, retry and a job's failure class from typed values (runner classes, sentinel
// errors), never from what an error says: an attempt's error can quote the model's own output, so a
// model that prints "connection refused" would otherwise pick its own class. A package's test runs
// Check over the package's directory and fails on any finding.
//
// It finds, in the non-test files of one directory:
//
//   - an import of regexp (the core matches no pattern on anything);
//   - a call of an Error method with no argument (err.Error()) whose result is matched: passed,
//     directly or through string conversion, to a function of strings or bytes, compared with ==
//     or !=, used as a switch tag, or indexed or sliced;
//   - a call of a function of strings or bytes whose argument is fmt.Sprint, Sprintf or Sprintln
//     of something (the same match, spelled another way).
//
// It is a floor, not a proof: an error's text copied into a variable first and matched later is not
// followed. Review covers that; this catches the ordinary spellings.
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

// Check parses the non-test .go files of dir and returns every finding, sorted by position.
func Check(dir string) ([]Finding, error) {
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
		out = append(out, CheckFile(fset, f)...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pos.Filename != out[j].Pos.Filename {
			return out[i].Pos.Filename < out[j].Pos.Filename
		}
		return out[i].Pos.Line < out[j].Pos.Line
	})
	return out, nil
}

// CheckFile returns the findings of one parsed file.
func CheckFile(fset *token.FileSet, f *ast.File) []Finding {
	var out []Finding
	add := func(n ast.Node, what string) { out = append(out, Finding{Pos: fset.Position(n.Pos()), What: what}) }
	pkgs := map[string]string{} // local name -> import path, for strings, bytes and fmt
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if path == "regexp" {
			add(imp, "imports regexp")
		}
		local := filepath.Base(path)
		if imp.Name != nil {
			local = imp.Name.Name
		}
		switch path {
		case "strings", "bytes", "fmt":
			pkgs[local] = path
		}
	}
	textFunc := func(call *ast.CallExpr) bool {
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return false
		}
		p := pkgs[id.Name]
		return p == "strings" || p == "bytes"
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if textFunc(x) {
				for _, a := range x.Args {
					if isErrorText(a) {
						add(a, "an error's text passed to "+exprString(x.Fun))
					} else if isSprint(a, pkgs) {
						add(a, "a formatted value passed to "+exprString(x.Fun))
					}
				}
			}
		case *ast.BinaryExpr:
			if (x.Op == token.EQL || x.Op == token.NEQ) && (isErrorText(x.X) || isErrorText(x.Y)) {
				add(x, "an error's text compared")
			}
		case *ast.SwitchStmt:
			if x.Tag != nil && isErrorText(x.Tag) {
				add(x, "a switch on an error's text")
			}
		case *ast.IndexExpr:
			if isErrorText(x.X) {
				add(x, "an error's text indexed")
			}
		case *ast.SliceExpr:
			if isErrorText(x.X) {
				add(x, "an error's text sliced")
			}
		}
		return true
	})
	return out
}

// isErrorText reports whether e is x.Error() (no argument), possibly converted ([]byte(...),
// string(...)) or parenthesised.
func isErrorText(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return isErrorText(x.X)
	case *ast.CallExpr:
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" && len(x.Args) == 0 {
			return true
		}
		if len(x.Args) == 1 && isConversion(x.Fun) {
			return isErrorText(x.Args[0])
		}
	}
	return false
}

func isConversion(fun ast.Expr) bool {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name == "string"
	case *ast.ArrayType:
		id, ok := f.Elt.(*ast.Ident)
		return ok && f.Len == nil && (id.Name == "byte" || id.Name == "rune")
	}
	return false
}

func isSprint(e ast.Expr, pkgs map[string]string) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || pkgs[id.Name] != "fmt" {
		return false
	}
	switch sel.Sel.Name {
	case "Sprint", "Sprintf", "Sprintln":
		return true
	}
	return false
}

func exprString(e ast.Expr) string {
	if sel, ok := e.(*ast.SelectorExpr); ok {
		if id, ok := sel.X.(*ast.Ident); ok {
			return id.Name + "." + sel.Sel.Name
		}
	}
	return "a text function"
}
