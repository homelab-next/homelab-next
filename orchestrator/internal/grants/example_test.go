// SPDX-License-Identifier: Apache-2.0

package grants

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"
)

// repoRoot is the repository root, from this package's directory.
const repoRoot = "../../.."

// exampleSpec is the render spec whose committed output hnx mcp catalog render --client
// orchestrator writes; tests/mcp/test_mcp_clients.py fails when that output is stale, and this
// test loads it in place, so the Python render and this loader cannot drift apart.
var exampleSpec = filepath.Join(repoRoot, "examples/mcp/clients/orchestrator.yml")

type renderSpec struct {
	Client        string `yaml:"client"`
	CheckProfiles string `yaml:"check_profiles"`
	Outputs       []struct {
		Path string `yaml:"path"`
	} `yaml:"outputs"`
}

// TestThePythonRenderOfExamplesMCPLoads: the catalog the render wrote loads, and every profile the
// spec's check_profiles names renders both lanes against it, exactly as the controller would.
func TestThePythonRenderOfExamplesMCPLoads(t *testing.T) {
	raw, err := os.ReadFile(exampleSpec)
	if err != nil {
		t.Fatal(err)
	}
	var spec renderSpec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Client != "orchestrator" || len(spec.Outputs) != 1 || spec.CheckProfiles == "" {
		t.Fatalf("unexpected spec: %+v", spec)
	}
	base := filepath.Dir(exampleSpec)
	cat, err := LoadCatalog(filepath.Join(base, spec.Outputs[0].Path), testZones)
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(base, spec.CheckProfiles))
	if err != nil || len(files) == 0 {
		t.Fatalf("check_profiles %q names no file (%v)", spec.CheckProfiles, err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var p struct {
			AgentKey string `yaml:"agent_key"`
			Grants   Set    `yaml:"grants"`
		}
		if err := yaml.Unmarshal(data, &p); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if p.Grants.IsZero() {
			t.Fatalf("%s: no grants block", f)
		}
		for _, shadow := range []bool{false, true} {
			got, err := cat.Render(p.Grants.Lane(shadow), Owner{AgentKey: p.AgentKey, Shadow: shadow})
			if err != nil {
				t.Errorf("%s (shadow=%v): %v", f, shadow, err)
			}
			if len(got) != len(p.Grants.Lane(shadow)) {
				t.Errorf("%s (shadow=%v): %d servers rendered for %d grants", f, shadow, len(got), len(p.Grants.Lane(shadow)))
			}
		}
		// The render pins a parameter to the values it rendered: another value is refused.
		for _, g := range p.Grants.Real {
			for key := range g.Env {
				bad := g
				bad.Env = map[string]string{key: "agents/someone-else/"}
				if _, err := cat.Render([]Grant{bad}, Owner{AgentKey: p.AgentKey}); !errors.Is(err, ErrInvalid) {
					t.Errorf("%s: %s=%q off its pins rendered (err %v)", f, key, bad.Env[key], err)
				}
			}
		}
	}
}
