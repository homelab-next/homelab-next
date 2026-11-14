// SPDX-License-Identifier: Apache-2.0

package gatewaytag

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The tag the gateway reads and the job record carries is one shape: the Go patterns are the
// event schema's, read in place (the schema's trailing "(?!\n)" makes Python's "$" mean end of
// text, which Go's "$" already does without the m flag).
func TestPatternsAreTheEventSchemas(t *testing.T) {
	data, err := os.ReadFile("../../../schemas/events/agent.job.finished.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Defs struct {
			RunID struct {
				Pattern string `json:"pattern"`
			} `json:"run_id"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSuffix(doc.Defs.RunID.Pattern, `(?!\n)`); got != RunIDPattern {
		t.Errorf("run_id pattern %q, Go has %q", got, RunIDPattern)
	}
	// gateway_tag sits deep in the data's properties: find its one pattern by its key
	var patterns []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				if m, ok := c.(map[string]any); ok && k == "gateway_tag" {
					if p, ok := m["pattern"].(string); ok {
						patterns = append(patterns, p)
					}
				}
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	var all any
	if err := json.Unmarshal(data, &all); err != nil {
		t.Fatal(err)
	}
	walk(all)
	if len(patterns) != 1 || strings.TrimSuffix(patterns[0], `(?!\n)`) != Pattern {
		t.Errorf("gateway_tag patterns %q, Go has %q", patterns, Pattern)
	}
}

func TestValid(t *testing.T) {
	for _, ok := range []string{"run-1", "job:run-1", "site/a:run.7", strings.Repeat("p", 64) + strings.Repeat("r", 128)} {
		if !Valid(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "a,b", "a b", "run\n", "x/", strings.Repeat("r", 193)} {
		if Valid(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if !ValidRunID("run-1") || ValidRunID("a/b") || ValidRunID("") {
		t.Error("ValidRunID")
	}
	if !ValidPrefix("") || !ValidPrefix("site/") || ValidPrefix("a,b") || ValidPrefix(strings.Repeat("p", 65)) {
		t.Error("ValidPrefix")
	}
}
