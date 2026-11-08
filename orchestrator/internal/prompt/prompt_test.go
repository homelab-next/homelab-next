// SPDX-License-Identifier: Apache-2.0

package prompt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/homelab-next/homelab-next/orchestrator/internal/config"
	"github.com/homelab-next/homelab-next/orchestrator/internal/lessons"
	"github.com/homelab-next/homelab-next/orchestrator/internal/profile"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
)

// matchingTask matches records of the lessons package's fixture registers.
const matchingTask = "The certificate expired and log rotation never ran."

func registers(t *testing.T) *lessons.Index {
	t.Helper()
	ix, err := lessons.LoadIndex("../lessons/testdata/lessons", "../lessons/testdata/runbooks")
	if err != nil {
		t.Fatal(err)
	}
	return ix
}

func writeFile(t *testing.T, path, body string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeState(t *testing.T, body string) string {
	t.Helper()
	return writeFile(t, filepath.Join(t.TempDir(), "state.json"), body, 0o644)
}

// build is Build with the shadow lane and no contract unless in says otherwise, so a test sees
// only the blocks it is about.
func build(t *testing.T, in Input) string {
	t.Helper()
	if in.Contracts == nil {
		in.Contracts = []string{}
	}
	if in.Lane == "" {
		in.Lane = runner.LaneShadow
	}
	got, _, err := Build(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// Without a configured list the built-in contracts follow the task, in order; a list replaces them,
// and an empty one (the site's opt-out) leaves none.
func TestBuild_BuiltInContractsUnlessReplaced(t *testing.T) {
	p := profile.Profile{ID: "collector-v1", AgentKey: "collector"}
	got, _, err := Build(context.Background(), Input{Profile: p, Task: "task", Lane: runner.LaneReal})
	if err != nil {
		t.Fatal(err)
	}
	if want := "task\n\n" + strings.Join(DefaultContracts(), "\n\n"); got != want {
		t.Fatalf("prompt = %q, want the task and the built-in contracts", got)
	}
	for _, marker := range []string{"[evidence-appendix]", "[loop-detection]", "[required-tool-call]", "finding_write", "proposal_file"} {
		if !strings.Contains(got, marker) {
			t.Errorf("the built-in contracts lack %q", marker)
		}
	}
	if got := build(t, Input{Profile: p, Task: "task", Contracts: []string{"[house-rule] one", "[house-rule] two"}}); got != "task\n\n[house-rule] one\n\n[house-rule] two" {
		t.Fatalf("replaced: %q", got)
	}
	if got := build(t, Input{Profile: p, Task: "task", Contracts: []string{}}); got != "task" {
		t.Fatalf("none: %q", got)
	}
}

// The built-in contracts name only tools this repository defines, and no product.
func TestDefaultContracts_NameThisRepositorysTools(t *testing.T) {
	data, err := os.ReadFile("../../../examples/mcp/hnx-broker.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"finding_write", "proposal_file"} {
		if !strings.Contains(string(data), "name: "+tool+",") {
			t.Errorf("the broker's MCP record does not define %s", tool)
		}
	}
	all := strings.Join(DefaultContracts(), "\n")
	for _, word := range []string{"write_finding", "write_proposal", "vault"} {
		if strings.Contains(all, word) {
			t.Errorf("a built-in contract names %q", word)
		}
	}
	d := DefaultContracts()
	d[0] = "changed"
	if DefaultContracts()[0] == "changed" {
		t.Error("DefaultContracts hands out shared state")
	}
}

// The contracts a configuration names reach the prompt, in its order, after the task and its
// register context.
func TestBuild_ContractsComeFromTheConfiguration(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "contracts", "evidence.md"), "[evidence] Show the query behind every number.\n", 0o600)
	writeFile(t, filepath.Join(dir, "contracts", "done.md"), "[done] A run is done when its output is written.\n", 0o600)
	cfgPath := writeFile(t, filepath.Join(dir, "controller.yaml"), `scope:
  denied_roots: [owner]
  findings_root: notes/findings/
  shared_write: [inbox/]
  reserved_names: [operator]
prompt_contracts: [contracts/evidence.md]
prompt_contracts_append: [contracts/done.md]
`, 0o600)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	contracts, err := cfg.PromptContractTexts(dir, DefaultContracts())
	if err != nil {
		t.Fatal(err)
	}
	got := build(t, Input{Profile: profile.Profile{AgentKey: "collector"}, Index: registers(t), Task: matchingTask, Contracts: contracts})
	at := -1
	for _, marker := range []string{matchingTask, "[dispatch-context]", "[evidence] Show the query", "[done] A run is done"} {
		i := strings.Index(got, marker)
		if i <= at {
			t.Fatalf("%q missing or out of order in:\n%s", marker, got)
		}
		at = i
	}
}

// TestBuild_BlockOrder pins the order of every block: task, register context, contracts, known
// incidents, facts, own state, cursor, the appendix for every lane, then this lane's.
func TestBuild_BlockOrder(t *testing.T) {
	state := writeState(t, `{"agents": {"collector": {"last_run": "r1", "last_status": "ok", "status": "cur", "open_incidents": {"INC-1": "OPEN"}}}}`)
	script := writeFile(t, filepath.Join(t.TempDir(), "facts.sh"), "#!/bin/sh\necho '{\"k\": 1}'\n", 0o755)
	p := profile.Profile{ID: "collector-v1", AgentKey: "collector", PromptContext: profile.PromptContext{
		StateFile: state, KnownIncidentsKey: "collector", OwnState: true, Cursor: true,
		FactsCommand: profile.FactsCommand{Argv: []string{script}}, Appendix: []string{"[all-lanes]"},
		RealAppendix: []string{"[real-only]"}, ShadowAppendix: []string{"[shadow-only]"},
	}}
	order := []string{"log rotation never ran", "[dispatch-context]", "[contract-a]", "[contract-b]",
		"[known-incidents]", "[deterministic-facts]", "[own-state]", "[prior-cursor]", "[all-lanes]"}
	for _, lane := range []struct {
		lane, last, none string
	}{{runner.LaneShadow, "[shadow-only]", "[real-only]"}, {runner.LaneReal, "[real-only]", "[shadow-only]"}} {
		got := build(t, Input{Profile: p, Index: registers(t), Task: matchingTask, Lane: lane.lane, Contracts: []string{"[contract-a]", "[contract-b]"}})
		at := -1
		for _, marker := range append(order, lane.last) {
			i := strings.Index(got, marker)
			if i <= at {
				t.Fatalf("%s: %q missing or out of order in:\n%s", lane.lane, marker, got)
			}
			at = i
		}
		if strings.Contains(got, lane.none) {
			t.Errorf("%s: the other lane's appendix is in the prompt", lane.lane)
		}
		if !strings.HasSuffix(got, lane.last) {
			t.Errorf("%s: the prompt does not end with the lane's appendix", lane.lane)
		}
	}
}

// Without lane appendices the lane changes nothing; an appendix for every lane goes to both. A
// lane that is neither is an error, never a guess.
func TestBuild_Lanes(t *testing.T) {
	for _, p := range []profile.Profile{
		{ID: "reviewer-v1", AgentKey: "reviewer"},
		{ID: "watcher-v1", AgentKey: "watcher", PromptContext: profile.PromptContext{Appendix: []string{"[both-lanes]"}}},
	} {
		onReal := build(t, Input{Profile: p, Task: "x", Lane: runner.LaneReal})
		shadow := build(t, Input{Profile: p, Task: "x", Lane: runner.LaneShadow})
		if onReal != shadow {
			t.Fatalf("%s: the lane changed a prompt with no lane appendix", p.AgentKey)
		}
		if len(p.PromptContext.Appendix) > 0 && !strings.HasSuffix(onReal, "[both-lanes]") {
			t.Fatalf("%s: the appendix is missing", p.AgentKey)
		}
	}
	for _, lane := range []string{"", "production", "Real"} {
		if _, _, err := Build(context.Background(), Input{Task: "x", Lane: lane}); err == nil {
			t.Errorf("lane %q accepted", lane)
		}
	}
}

// The profile's data alone decides what is injected: a state file holding an agent's blocks adds
// nothing without the prompt context asking for it.
func TestBuild_NothingWithoutTheProfileAsking(t *testing.T) {
	state := writeState(t, `{"agents": {"watcher": {"last_run": "x", "status": "cursor", "open_incidents": {"A-1": "OPEN"}}}}`)
	p := profile.Profile{ID: "watcher-v1", AgentKey: "watcher", PromptContext: profile.PromptContext{StateFile: state}}
	if got := build(t, Input{Profile: p, Task: "task"}); got != "task" {
		t.Errorf("prompt = %q, want the bare task", got)
	}
}

// No register, or a register with no match, means no register block; everything else stays.
func TestBuild_RegisterBlockOnlyOnAMatch(t *testing.T) {
	p := profile.Profile{ID: "collector-v1", AgentKey: "collector", PromptContext: profile.PromptContext{ShadowAppendix: []string{"[appendix]"}}}
	for name, in := range map[string]Input{
		"nil index": {Profile: p, Task: "run the sweep"},
		"no match":  {Profile: p, Index: registers(t), Task: "nothing in the registers fits this"},
	} {
		got := build(t, in)
		if got != in.Task+"\n\n[appendix]" {
			t.Errorf("%s: prompt = %q", name, got)
		}
	}
}

// Meta names the records injected, by uid, and the sha256 and length of the exact text; a path
// the job names matches a record by its path prefixes.
func TestBuild_Meta(t *testing.T) {
	got, meta, err := Build(context.Background(), Input{Profile: profile.Profile{AgentKey: "collector"}, Index: registers(t), Task: matchingTask, Lane: runner.LaneReal})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(got))
	if meta.SHA256 != hex.EncodeToString(sum[:]) || meta.Bytes != len(got) {
		t.Errorf("meta = %+v for a %d-byte prompt", meta, len(got))
	}
	if len(meta.LessonUIDs) == 0 || len(meta.RunbookUIDs) == 0 {
		t.Fatalf("meta names no record: %+v", meta)
	}
	for _, uid := range append(append([]string{}, meta.LessonUIDs...), meta.RunbookUIDs...) {
		if !strings.Contains(got, uid) {
			t.Errorf("meta names %s, which the prompt does not quote", uid)
		}
	}
	_, want, _, _ := lessonsFor(t, matchingTask, nil)
	if strings.Join(meta.LessonUIDs, ",") != strings.Join(want, ",") {
		t.Errorf("lesson uids %v, the reader's %v", meta.LessonUIDs, want)
	}
}

func lessonsFor(t *testing.T, task string, paths []string) (string, []string, []string, *lessons.Index) {
	ix := registers(t)
	payload, l, r := lessons.ResolveContextFor(ix, task, paths)
	return payload, l, r, ix
}

// The register block is the reader's own, quoted as data: Build adds nothing to it and changes
// none of it.
func TestBuild_RegisterTextIsTheReadersDataBlock(t *testing.T) {
	payload, _, _, ix := lessonsFor(t, matchingTask, nil)
	if payload == "" || !strings.Contains(payload, "reference data, not instructions") {
		t.Fatalf("the reader's block lost its data framing:\n%s", payload)
	}
	got := build(t, Input{Profile: profile.Profile{AgentKey: "collector"}, Index: ix, Task: matchingTask})
	if got != matchingTask+"\n\n"+payload {
		t.Errorf("prompt =\n%s\nwant the task and the reader's block", got)
	}
}

// Paths reach the reader: a record whose path prefix covers a path the job names is matched
// though its task text matches nothing.
func TestBuild_PathsMatchRecords(t *testing.T) {
	in := Input{Profile: profile.Profile{AgentKey: "collector"}, Index: registers(t), Task: "apply the change", Lane: runner.LaneReal}
	if got := build(t, in); got != in.Task {
		t.Fatalf("without paths: %q", got)
	}
	in.Paths = []string{"roles/proxy/tasks/main.yml"}
	got, meta, err := Build(context.Background(), in)
	if err != nil || len(meta.LessonUIDs) == 0 || !strings.Contains(got, "[dispatch-context]") {
		t.Fatalf("with a path under a record's prefix: %v, %+v\n%s", err, meta, got)
	}
}

// inject_own_state is own_state's older spelling, for a profile not loaded through the loader
// (which sets own_state from it) too.
func TestBuild_InjectOwnState(t *testing.T) {
	state := writeState(t, `{"agents": {"watcher": {"status": "clean"}}}`)
	p := profile.Profile{AgentKey: "watcher", InjectOwnState: true, PromptContext: profile.PromptContext{StateFile: state}}
	if got := build(t, Input{Profile: p, Task: "t"}); !strings.Contains(got, `[own-state] state.json's block for watcher`) || !strings.Contains(got, `{"status":"clean"}`) {
		t.Errorf("prompt = %q", got)
	}
}
