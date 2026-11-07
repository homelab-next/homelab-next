// SPDX-License-Identifier: Apache-2.0

package events

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The schemas the controller's events must satisfy, read in place from schemas/events: the
// envelope for every event, and the data contracts of the two job events that have one.
var emittedStems = []string{"envelope", "agent.job.finished", "agent.job.failed"}

func mustValidator(t *testing.T) *validator {
	t.Helper()
	v, err := loadValidator()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func mustID(t *testing.T, v *validator, stem string) string {
	t.Helper()
	id, err := v.schemaIDOf(stem)
	if err != nil || id == "" {
		t.Fatalf("schema %s: %q, %v", stem, id, err)
	}
	return id
}

// The validator agrees with the schemas' own fixtures: every example of these schemas is valid,
// every negative invalid, and nothing is beyond what the validator implements. Without this the
// tests below could pass on a validator that accepts everything.
func TestSchemaValidatorAgreesWithTheRepositoryFixtures(t *testing.T) {
	v := mustValidator(t)
	for _, stem := range emittedStems {
		id := mustID(t, v, stem)
		for _, kind := range []string{"examples", "negative"} {
			files, _ := filepath.Glob(filepath.Join("../../../schemas/events", kind, stem+".*.json"))
			var own []string
			for _, f := range files {
				// "agent.job.failed.x.json" also matches a stem "agent.job" would; take only
				// the files whose stem is exactly this one (the rest is the label)
				label := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), stem+"."), ".json")
				if !strings.Contains(label, ".") {
					own = append(own, f)
				}
			}
			if len(own) == 0 {
				t.Fatalf("%s: no %s to check the validator against", stem, kind)
			}
			for _, f := range own {
				doc, err := readJSON(f)
				if err != nil {
					t.Fatal(err)
				}
				r := v.validate(id, doc)
				if len(r.unsupported) > 0 {
					t.Errorf("%s: the validator cannot judge it: %v", f, r.unsupported)
				}
				if kind == "examples" && len(r.errs) > 0 {
					t.Errorf("example %s is refused: %v", f, r.errs)
				}
				if kind == "negative" && len(r.errs) == 0 {
					t.Errorf("negative %s is accepted", f)
				}
			}
		}
	}
}

func assertValid(t *testing.T, v *validator, stem string, e Event) {
	t.Helper()
	body, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	r := v.validate(mustID(t, v, stem), doc)
	if len(r.unsupported) > 0 || len(r.errs) > 0 {
		t.Fatalf("%s envelope %s\nrefused: %v\nunsupported: %v", stem, body, r.errs, r.unsupported)
	}
}

func finishedData(runID string) map[string]any {
	return map[string]any{
		"run_id": runID, "profile": "profile:watcher", "profile_revision": "rev-3", "lane": "real",
		"outcome": "failed", "failure_class": "stall", "retry_of_run_id": nil,
		"auto_retry_scheduled": false, "local_attempts": 2, "cloud_fallback_used": false,
		"backend": "engine-a", "model": "local/model-v1", "queued_at": "2026-01-01T00:00:00Z",
		"started_at": "2026-01-01T00:00:05Z", "finished_at": "2026-01-01T00:01:05.25Z",
		"queue_wait_s": 5.0, "wall_s": 60.25, "input_bytes": 120, "output_bytes": nil,
		"usage": map[string]any{
			"input_tokens": 900, "output_tokens": 40, "reasoning_tokens": nil,
			"cache_read_tokens": 0, "api_calls": 2, "cost_usd": nil,
		},
		"turn_exit_reason": "stalled", "tools": []any{map[string]any{"name": "read_file", "calls": 3}},
		"gateway_tag": "job:" + runID,
	}
}

// What the package builds, with its default source, validates against the schemas in place: the
// envelope of every event (agent.job.started has no data contract of its own), and the job
// events' data contracts.
func TestEmittedEnvelopesValidateAgainstTheSchemasInPlace(t *testing.T) {
	v := mustValidator(t)
	at := time.Date(2026, 1, 1, 0, 1, 5, 250000000, time.UTC)
	run := "run-7f3a"
	started := New("homelabnext.agent.job.started", DefaultSource, run, run+":homelabnext.agent.job.started", at,
		map[string]any{"run_id": run, "agent_key": "watcher"})
	assertValid(t, v, "envelope", started)

	failed := New("homelabnext.agent.job.failed", DefaultSource, run, run+":homelabnext.agent.job.failed", at,
		map[string]any{"run_id": run, "agent_key": "watcher", "profile": "profile:watcher", "state": "failed",
			"reason": "stall", "failure_class": "stall", "attempts": 2, "resubmits": 0, "priority": 50})
	assertValid(t, v, "agent.job.failed", failed)
	assertValid(t, v, "envelope", failed)

	finished := New("homelabnext.agent.job.finished", DefaultSource, run, run+":homelabnext.agent.job.finished", at, finishedData(run))
	finished.CorrelationID = run
	assertValid(t, v, "agent.job.finished", finished)

	// an event built with no data still carries the object the envelope requires
	assertValid(t, v, "envelope", New("homelabnext.agent.job.started", DefaultSource, run, "k", at, nil))
}

// The checks above can fail: an envelope the package could be misused to build is refused.
func TestSchemaValidatorRefusesABadEnvelope(t *testing.T) {
	v := mustValidator(t)
	at := time.Unix(0, 0)
	for name, e := range map[string]Event{
		"url source":   New("homelabnext.agent.job.started", "https://ctl.example.internal", "r", "k", at, nil),
		"foreign type": New("agent.job.started", DefaultSource, "r", "k", at, nil),
		"spec version": func() Event {
			e := New("homelabnext.agent.job.started", DefaultSource, "r", "k", at, nil)
			e.SpecVersion = "0.3"
			return e
		}(),
		"text in data":  New("homelabnext.agent.job.finished", DefaultSource, "r", "k", at, func() map[string]any { d := finishedData("r"); d["task"] = "free text"; return d }()),
		"model address": New("homelabnext.agent.job.finished", DefaultSource, "r", "k", at, func() map[string]any { d := finishedData("r"); d["model"] = "http://x/y"; return d }()),
	} {
		stem := "envelope"
		if e.Type == "homelabnext.agent.job.finished" {
			stem = "agent.job.finished"
		}
		body, _ := json.Marshal(e)
		var doc any
		_ = json.Unmarshal(body, &doc)
		r := v.validate(mustID(t, v, stem), doc)
		if len(r.unsupported) > 0 || len(r.errs) == 0 {
			t.Errorf("%s: accepted (unsupported %v)", name, r.unsupported)
		}
	}
}

// ValidSource is the schema's svc_id rule: the same pattern and the same length bound, read in
// place from schemas/ids/logical-id.schema.json.
func TestValidSourceIsTheSchemasSvcID(t *testing.T) {
	doc, err := readJSON("../../../schemas/ids/logical-id.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	def := doc.(map[string]any)["$defs"].(map[string]any)["svc_id"].(map[string]any)
	if got := strings.ReplaceAll(def["pattern"].(string), `$(?!\n)`, `$`); got != svcID.String() {
		t.Fatalf("svc_id pattern %q, the package's %q", got, svcID.String())
	}
	if def["maxLength"].(float64) != 128 {
		t.Fatalf("svc_id maxLength %v, the package's 128", def["maxLength"])
	}
}
