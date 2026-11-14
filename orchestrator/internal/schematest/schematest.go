// SPDX-License-Identifier: Apache-2.0

// Package schematest validates JSON against this repository's id, event and platform schemas,
// read in place, for the controller's tests: what a package emits is held to schemas/ itself,
// with the standard library only. Only _test.go files import it (TestOnlyTestsImportIt).
package schematest

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// A JSON Schema (draft 2020-12) Validator for the subset of the language this repository's
// event and id schemas use. It fails closed: a keyword it does not implement, a $ref it cannot
// resolve or a pattern it cannot translate is reported as unsupported, and every test treats
// unsupported as a failure, never as a pass. package events' schema_test.go checks the Validator
// itself against the schemas' own examples and negatives.

// Validator holds the schemas under one schemas directory, by $id.
type Validator struct {
	dir      string
	byID     map[string]any
	patterns map[string]*pattern
}

// Result is one validation: Errs are the instance's faults, Unsupported what the Validator could
// not judge.
type Result struct {
	Errs        []string
	Unsupported []string
}

func (r *Result) fail(at, format string, a ...any) {
	r.Errs = append(r.Errs, at+": "+fmt.Sprintf(format, a...))
}

func (r *Result) cannot(at, format string, a ...any) {
	r.Unsupported = append(r.Unsupported, at+": "+fmt.Sprintf(format, a...))
}

// Load reads every schema under schemasDir's ids, events and platform directories (the
// repository's schemas/, given relative to the calling test's package).
func Load(schemasDir string) (*Validator, error) {
	v := &Validator{dir: schemasDir, byID: map[string]any{}, patterns: map[string]*pattern{}}
	for _, dir := range []string{filepath.Join(schemasDir, "ids"), filepath.Join(schemasDir, "events"), filepath.Join(schemasDir, "platform")} {
		files, err := filepath.Glob(filepath.Join(dir, "*.schema.json"))
		if err != nil || len(files) == 0 {
			return nil, fmt.Errorf("no schemas under %s (%v)", dir, err)
		}
		for _, f := range files {
			doc, err := ReadJSON(f)
			if err != nil {
				return nil, err
			}
			m, _ := doc.(map[string]any)
			id, _ := m["$id"].(string)
			if id == "" {
				return nil, fmt.Errorf("%s has no $id", f)
			}
			v.byID[id] = doc
		}
	}
	return v, nil
}

// ReadJSON decodes the JSON file at path.
func ReadJSON(path string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return doc, nil
}

// SchemaIDOf returns the $id of the schema file stem (as in "agent.job.finished") under
// schemas/events.
func (v *Validator) SchemaIDOf(stem string) (string, error) {
	doc, err := ReadJSON(filepath.Join(v.dir, "events", stem+".schema.json"))
	if err != nil {
		return "", err
	}
	id, _ := doc.(map[string]any)["$id"].(string)
	return id, nil
}

// ValidateStem checks inst, a value JSON-encoded and decoded again, against the events schema of
// the file stem (as in "agent.job.finished").
func (v *Validator) ValidateStem(stem string, inst any) (Result, error) {
	id, err := v.SchemaIDOf(stem)
	if err != nil {
		return Result{}, err
	}
	b, err := json.Marshal(inst)
	if err != nil {
		return Result{}, err
	}
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		return Result{}, err
	}
	return v.Validate(id, doc), nil
}

// Validate checks inst against the schema with the given $id.
func (v *Validator) Validate(id string, inst any) Result {
	var r Result
	s, ok := v.byID[id]
	if !ok {
		r.cannot("", "no schema with $id %s", id)
		return r
	}
	v.check(s, id, inst, "$", &r)
	return r
}

var annotations = map[string]bool{
	"$schema": true, "$id": true, "$defs": true, "$comment": true, "title": true, "description": true,
	"examples": true, "default": true, "deprecated": true, "readOnly": true, "writeOnly": true,
	// format is an annotation in draft 2020-12 unless a vocabulary asserts it; these schemas
	// pattern-check what they mean to assert
	"format": true,
	// handled by "if"
	"then": true, "else": true,
}

func (v *Validator) check(schema any, base string, inst any, at string, r *Result) {
	baseURI := base
	switch s := schema.(type) {
	case bool:
		if !s {
			r.fail(at, "the schema false admits nothing")
		}
		return
	case map[string]any:
		if id, ok := s["$id"].(string); ok {
			baseURI = id
		}
		keys := make([]string, 0, len(s))
		for k := range s {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v.keyword(s, k, baseURI, inst, at, r)
		}
	default:
		r.cannot(at, "a schema that is neither an object nor a boolean")
	}
}

func (v *Validator) keyword(s map[string]any, k, base string, inst any, at string, r *Result) {
	val := s[k]
	if annotations[k] || strings.HasPrefix(k, "x-") {
		return
	}
	switch k {
	case "$ref":
		ref, _ := val.(string)
		target, targetBase, err := v.resolve(ref, base)
		if err != nil {
			r.cannot(at, "%v", err)
			return
		}
		v.check(target, targetBase, inst, at, r)
	case "allOf", "anyOf", "oneOf":
		subs, _ := val.([]any)
		passed := 0
		for _, sub := range subs {
			var sr Result
			v.check(sub, base, inst, at, &sr)
			r.Unsupported = append(r.Unsupported, sr.Unsupported...)
			if len(sr.Errs) == 0 {
				passed++
			} else if k == "allOf" {
				r.Errs = append(r.Errs, sr.Errs...)
			}
		}
		if k == "anyOf" && passed == 0 {
			r.fail(at, "matches none of anyOf")
		}
		if k == "oneOf" && passed != 1 {
			r.fail(at, "matches %d of oneOf, not exactly one", passed)
		}
	case "not":
		var sr Result
		v.check(val, base, inst, at, &sr)
		r.Unsupported = append(r.Unsupported, sr.Unsupported...)
		if len(sr.Errs) == 0 {
			r.fail(at, "matches a schema under not")
		}
	case "if":
		var sr Result
		v.check(val, base, inst, at, &sr)
		r.Unsupported = append(r.Unsupported, sr.Unsupported...)
		branch := "else"
		if len(sr.Errs) == 0 {
			branch = "then"
		}
		if sub, ok := s[branch]; ok {
			v.check(sub, base, inst, at, r)
		}
	case "type":
		if !hasType(inst, val) {
			r.fail(at, "is not of type %v", val)
		}
	case "const":
		if !reflect.DeepEqual(inst, val) {
			r.fail(at, "is not the const %v", val)
		}
	case "enum":
		opts, _ := val.([]any)
		found := false
		for _, o := range opts {
			found = found || reflect.DeepEqual(inst, o)
		}
		if !found {
			r.fail(at, "is not one of %v", opts)
		}
	case "properties", "additionalProperties", "required", "propertyNames", "minProperties", "maxProperties":
		if obj, ok := inst.(map[string]any); ok {
			v.object(s, k, base, obj, at, r)
		}
	case "items", "minItems", "maxItems", "uniqueItems":
		if arr, ok := inst.([]any); ok {
			v.array(s, k, base, arr, at, r)
		}
	case "minLength", "maxLength", "pattern":
		if str, ok := inst.(string); ok {
			v.str(k, val, str, at, r)
		}
	case "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum":
		if n, ok := inst.(float64); ok {
			lim, _ := val.(float64)
			if (k == "minimum" && n < lim) || (k == "maximum" && n > lim) ||
				(k == "exclusiveMinimum" && n <= lim) || (k == "exclusiveMaximum" && n >= lim) {
				r.fail(at, "%v breaks %s %v", n, k, lim)
			}
		}
	default:
		r.cannot(at, "unsupported keyword %q", k)
	}
}

func (v *Validator) object(s map[string]any, k, base string, obj map[string]any, at string, r *Result) {
	props, _ := s["properties"].(map[string]any)
	switch k {
	case "properties":
		for name, sub := range props {
			if inst, ok := obj[name]; ok {
				v.check(sub, base, inst, at+"."+name, r)
			}
		}
	case "additionalProperties":
		if _, ok := s["patternProperties"]; ok {
			return // reported as an unsupported keyword of its own
		}
		for name, inst := range obj {
			if _, declared := props[name]; !declared {
				v.check(s[k], base, inst, at+"."+name, r)
			}
		}
	case "required":
		req, _ := s[k].([]any)
		for _, name := range req {
			if _, ok := obj[name.(string)]; !ok {
				r.fail(at, "lacks the required %q", name)
			}
		}
	case "propertyNames":
		for name := range obj {
			v.check(s[k], base, name, at+"."+name+" (name)", r)
		}
	case "minProperties", "maxProperties":
		lim, _ := s[k].(float64)
		if (k == "minProperties" && float64(len(obj)) < lim) || (k == "maxProperties" && float64(len(obj)) > lim) {
			r.fail(at, "has %d properties, against %s %v", len(obj), k, lim)
		}
	}
}

func (v *Validator) array(s map[string]any, k, base string, arr []any, at string, r *Result) {
	switch k {
	case "items":
		for i, inst := range arr {
			v.check(s[k], base, inst, fmt.Sprintf("%s[%d]", at, i), r)
		}
	case "minItems", "maxItems":
		lim, _ := s[k].(float64)
		if (k == "minItems" && float64(len(arr)) < lim) || (k == "maxItems" && float64(len(arr)) > lim) {
			r.fail(at, "has %d items, against %s %v", len(arr), k, lim)
		}
	case "uniqueItems":
		if s[k] == true {
			for i := range arr {
				for j := i + 1; j < len(arr); j++ {
					if reflect.DeepEqual(arr[i], arr[j]) {
						r.fail(at, "items %d and %d are equal", i, j)
					}
				}
			}
		}
	}
}

func (v *Validator) str(k string, val any, str, at string, r *Result) {
	switch k {
	case "minLength", "maxLength":
		lim, _ := val.(float64)
		n := float64(utf8.RuneCountInString(str))
		if (k == "minLength" && n < lim) || (k == "maxLength" && n > lim) {
			r.fail(at, "is %v characters long, against %s %v", n, k, lim)
		}
	case "pattern":
		src, _ := val.(string)
		p, err := v.pattern(src)
		if err != nil {
			r.cannot(at, "pattern %q: %v", src, err)
			return
		}
		if !p.match(str) {
			r.fail(at, "%q does not match %q", str, src)
		}
	}
}

func hasType(inst, want any) bool {
	if list, ok := want.([]any); ok {
		for _, w := range list {
			if hasType(inst, w) {
				return true
			}
		}
		return false
	}
	switch want {
	case "null":
		return inst == nil
	case "boolean":
		_, ok := inst.(bool)
		return ok
	case "object":
		_, ok := inst.(map[string]any)
		return ok
	case "array":
		_, ok := inst.([]any)
		return ok
	case "string":
		_, ok := inst.(string)
		return ok
	case "number":
		_, ok := inst.(float64)
		return ok
	case "integer":
		n, ok := inst.(float64)
		return ok && n == math.Trunc(n) && !math.IsInf(n, 0)
	}
	return false
}

// resolve finds the schema a $ref names: an absolute $id or the current base, then a JSON
// pointer fragment.
func (v *Validator) resolve(ref, base string) (any, string, error) {
	uri, frag, _ := strings.Cut(ref, "#")
	if uri == "" {
		uri = base
	}
	doc, ok := v.byID[uri]
	if !ok {
		return nil, "", fmt.Errorf("$ref %q: no schema with $id %s", ref, uri)
	}
	cur := doc
	if frag != "" {
		for _, tok := range strings.Split(strings.TrimPrefix(frag, "/"), "/") {
			tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, "", fmt.Errorf("$ref %q: %q is not inside an object", ref, tok)
			}
			if cur, ok = m[tok]; !ok {
				return nil, "", fmt.Errorf("$ref %q: no %q", ref, tok)
			}
		}
	}
	return cur, uri, nil
}

// pattern is an ECMA-262/Python-style pattern translated to RE2. RE2 has no lookaround, so the
// two shapes these schemas use are rewritten exactly:
//
//   - "$(?!\n)" is "end of input, not before a final newline". Go's "$" (without the m flag) is
//     already end of input only, so the lookahead is dropped.
//   - leading negative lookaheads "^(?!A)(?!B)REST": the string matches when "^REST" matches and
//     no "^A", "^B" does. A lookahead body ending in a negative lookahead of one character class,
//     "X(?![C])", becomes "X(?:[^C]|$)", which is the same condition on a prefix.
//
// Anything else RE2 cannot compile is unsupported.
type pattern struct {
	main   *regexp.Regexp
	forbid []*regexp.Regexp
}

func (p *pattern) match(s string) bool {
	if !p.main.MatchString(s) {
		return false
	}
	for _, f := range p.forbid {
		if f.MatchString(s) {
			return false
		}
	}
	return true
}

func (v *Validator) pattern(src string) (*pattern, error) {
	if p, ok := v.patterns[src]; ok {
		return p, nil
	}
	p, err := translatePattern(src)
	if err != nil {
		return nil, err
	}
	v.patterns[src] = p
	return p, nil
}

func translatePattern(src string) (*pattern, error) {
	s := strings.ReplaceAll(src, `$(?!\n)`, `$`)
	p := &pattern{}
	if strings.HasPrefix(s, "^(?!") {
		rest := s[1:]
		for strings.HasPrefix(rest, "(?!") {
			end, err := groupEnd(rest)
			if err != nil {
				return nil, err
			}
			body := trailingClassLookahead(rest[3:end])
			re, err := regexp.Compile("^(?:" + body + ")")
			if err != nil {
				return nil, err
			}
			p.forbid = append(p.forbid, re)
			rest = rest[end+1:]
		}
		s = "^" + rest
	}
	re, err := regexp.Compile(s)
	if err != nil {
		return nil, err
	}
	p.main = re
	return p, nil
}

// groupEnd returns the index of the parenthesis closing the group s starts with, skipping
// escapes and character classes.
func groupEnd(s string) (int, error) {
	depth, inClass := 0, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			i++
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("unbalanced group in %q", s)
}

// trailingClassLookahead rewrites a body ending in "(?![C])" (C not negated) as "(?:[^C]|$)".
func trailingClassLookahead(body string) string {
	i := strings.LastIndex(body, "(?![")
	if i < 0 || !strings.HasSuffix(body, "])") || strings.HasPrefix(body[i+4:], "^") {
		return body
	}
	class := body[i+4 : len(body)-2]
	if strings.ContainsAny(class, "[]") {
		return body
	}
	return body[:i] + "(?:[^" + class + "]|$)"
}
