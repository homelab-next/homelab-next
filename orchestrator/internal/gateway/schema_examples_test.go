// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// schemaDir is the repository's schemas/platform, which holds the gateway config contract
// (gateway_config.schema.json) with its examples/ and negative/ instances. They are read in
// place, never copied, so an instance added to the contract is an instance this reader judges.
const schemaDir = "../../../schemas/platform"

func contractInstances(t *testing.T, kind string) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(schemaDir, kind, "gateway_config.*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no %s of the gateway config contract under %s", kind, schemaDir)
	}
	out := make(map[string][]byte, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(p)] = data
	}
	return out
}

// Every example the contract's schema accepts, this reader accepts.
func TestGatewayConfigAcceptsEverySchemaExample(t *testing.T) {
	for name, data := range contractInstances(t, "examples") {
		if _, err := ParseConfig(data); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Every negative the contract's schema refuses, this reader refuses.
func TestGatewayConfigRefusesEverySchemaNegative(t *testing.T) {
	for name, data := range contractInstances(t, "negative") {
		if _, err := ParseConfig(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
