// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gatewayPackages are the gateway's packages, relative to the module root.
var gatewayPackages = []string{"./cmd/gateway", "./internal/gateway"}

// The gateway stays standard library only (ADR-0026, amendment of 2026-11-07): the module has
// third-party dependencies for the controller, and none of them may reach the gateway's build.
// `go list -deps -test` of its packages, tests included, names only standard-library packages and
// the module's own.
func TestGatewayDependsOnlyOnTheStandardLibrary(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(string(mod), "\n")
	module := strings.TrimSpace(strings.TrimPrefix(first, "module "))
	if !strings.HasPrefix(first, "module ") || module == "" {
		t.Fatalf("go.mod does not start with its module line: %q", first)
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go command, which runs this test, is not on PATH: %v", err)
	}
	args := append([]string{"list", "-deps", "-test", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}"}, gatewayPackages...)
	cmd := exec.Command(goBin, args...)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("go list: %v\n%s", err, stderr)
	}
	own := 0
	for _, pkg := range strings.Fields(string(out)) {
		if strings.HasPrefix(pkg, "[") || strings.HasSuffix(pkg, "]") {
			continue // the "[x.test]" half of a test variant's import path
		}
		if pkg != module && !strings.HasPrefix(pkg, module+"/") {
			t.Errorf("the gateway depends on %s, which is neither the standard library nor this module", pkg)
		}
		own++
	}
	if own < len(gatewayPackages) {
		t.Fatalf("go list named %d of the module's packages, want at least the gateway's %d:\n%s", own, len(gatewayPackages), out)
	}
}
