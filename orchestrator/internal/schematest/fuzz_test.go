// SPDX-License-Identifier: Apache-2.0

package schematest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/homelab-next/homelab-next/orchestrator/internal/fuzzseed"
)

// FuzzSchemaSubset (ADR-0048 decision 1) holds the schema subset validator to its fail-closed
// contract on the repository's schemas, with the schemas' own examples and
// negatives as seeds and the fuzzer mutating them: it never panics, its verdict is pass, fail or
// unsupported and is the same on a second run, a combinator (allOf, anyOf, oneOf, not, if) never
// loses an unsupported verdict from under it, and an unsupported keyword beside the schema makes
// the verdict unsupported whatever the document. It moved here from internal/events with the
// validator (ADR-0048, implementation plan step 4).

// verdictRef reads a Result as one verdict.
type verdictRef func(r Result) string

// failClosed is the reference: anything the validator could not judge is unsupported, never a
// pass or a fail.
func failClosed(r Result) string {
	switch {
	case len(r.Unsupported) > 0:
		return "unsupported"
	case len(r.Errs) > 0:
		return "fail"
	}
	return "pass"
}

// errsOnly is the wrong reference: it reads a Result by its faults alone, so what the validator
// could not judge reads as a pass.
func errsOnly(r Result) string {
	if len(r.Errs) > 0 {
		return "fail"
	}
	return "pass"
}

// subsetTarget is one schema and the directory its examples and negatives are in.
type subsetTarget struct{ dir, stem, id string }

func subsetTargets(tb testing.TB, v *Validator) []subsetTarget {
	tb.Helper()
	var out []subsetTarget
	for _, dir := range []string{filepath.Join(v.dir, "ids"), filepath.Join(v.dir, "events"), filepath.Join(v.dir, "platform")} {
		files, err := filepath.Glob(filepath.Join(dir, "*.schema.json"))
		if err != nil || len(files) == 0 {
			tb.Fatalf("no schemas under %s (%v)", dir, err)
		}
		for _, f := range files {
			doc, err := ReadJSON(f)
			if err != nil {
				tb.Fatal(err)
			}
			id, _ := doc.(map[string]any)["$id"].(string)
			if _, ok := v.byID[id]; !ok {
				tb.Fatalf("%s: $id %q is not loaded", f, id)
			}
			out = append(out, subsetTarget{dir, strings.TrimSuffix(filepath.Base(f), ".schema.json"), id})
		}
	}
	return out
}

// subsetSeeds are every schema's own examples and negatives: (schema index, document).
func subsetSeeds(tb testing.TB, targets []subsetTarget) [][]any {
	tb.Helper()
	var out [][]any
	for i, t := range targets {
		for _, kind := range []string{"examples", "negative"} {
			files, _ := filepath.Glob(filepath.Join(t.dir, kind, t.stem+".*.json"))
			for _, f := range files {
				label := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), t.stem+"."), ".json")
				if strings.Contains(label, ".") {
					continue // another schema's, whose stem starts with this one
				}
				data, err := os.ReadFile(f)
				if err != nil {
					tb.Fatal(err)
				}
				out = append(out, []any{uint(i), data})
			}
		}
	}
	if len(out) < len(targets) {
		tb.Fatalf("only %d examples and negatives for %d schemas", len(out), len(targets))
	}
	return out
}

func sortedResult(r Result) Result {
	r.Errs, r.Unsupported = slices.Clone(r.Errs), slices.Clone(r.Unsupported)
	sort.Strings(r.Errs)
	sort.Strings(r.Unsupported)
	return r
}

func subsetProperty(verdict verdictRef, v *Validator, targets []subsetTarget, which uint, data []byte) error {
	var inst any
	if json.Unmarshal(data, &inst) != nil {
		return nil
	}
	t := targets[which%uint(len(targets))]
	base := v.Validate(t.id, inst)
	if again := v.Validate(t.id, inst); !reflect.DeepEqual(sortedResult(base), sortedResult(again)) {
		return fmt.Errorf("%s on %s: a second run gives %+v, the first %+v", t.stem, data, again, base)
	}
	bv := verdict(base)
	if bv != "pass" && bv != "fail" && bv != "unsupported" {
		return fmt.Errorf("%s on %s: verdict %q", t.stem, data, bv)
	}
	ref := map[string]any{"$ref": t.id}
	flip := map[string]string{"pass": "fail", "fail": "pass", "unsupported": "unsupported"}
	ifThen := "pass"
	if bv == "unsupported" {
		ifThen = "unsupported"
	}
	for _, w := range []struct {
		name   string
		schema map[string]any
		want   string
	}{
		{"allOf", map[string]any{"allOf": []any{ref}}, bv},
		{"anyOf", map[string]any{"anyOf": []any{ref}}, bv},
		{"oneOf", map[string]any{"oneOf": []any{ref}}, bv},
		{"not", map[string]any{"not": ref}, flip[bv]},
		{"if", map[string]any{"if": ref, "then": true, "else": true}, ifThen},
		{"an unsupported keyword beside it", map[string]any{"allOf": []any{ref}, "patternProperties": map[string]any{}}, "unsupported"},
	} {
		var r Result
		v.check(w.schema, t.id, inst, "$", &r)
		if got := verdict(r); got != w.want {
			return fmt.Errorf("%s on %s under %s: verdict %s, want %s (the schema alone: %s)", t.stem, data, w.name, got, w.want, bv)
		}
	}
	return nil
}

func FuzzSchemaSubset(f *testing.F) {
	v, err := Load("../../../schemas")
	if err != nil {
		f.Fatal(err)
	}
	targets := subsetTargets(f, v)
	for _, s := range subsetSeeds(f, targets) {
		f.Add(s[0].(uint), s[1].([]byte))
	}
	f.Fuzz(func(t *testing.T, which uint, data []byte) {
		if err := subsetProperty(failClosed, v, targets, which, data); err != nil {
			t.Fatal(err)
		}
	})
}

func subsetWith(verdict verdictRef, v *Validator, targets []subsetTarget) func([]any) error {
	return func(a []any) error { return subsetProperty(verdict, v, targets, a[0].(uint), a[1].([]byte)) }
}

func TestFuzzSchemaSubsetPropertyCanFail(t *testing.T) {
	v, err := Load("../../../schemas")
	if err != nil {
		t.Fatal(err)
	}
	targets := subsetTargets(t, v)
	seeds := append(fuzzseed.Corpus(t, "FuzzSchemaSubset"), subsetSeeds(t, targets)...)
	fuzzseed.HoldsAndCanFail(t, seeds, subsetWith(failClosed, v, targets), subsetWith(errsOnly, v, targets))
}
