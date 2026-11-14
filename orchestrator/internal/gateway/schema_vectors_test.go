// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"testing"
)

// configVectors is the repository's own conformance/fixtures/gateway_config_vectors.json, which
// the Python tests regenerate with the contract's schema (schemas/platform/gateway_config.schema.json).
// Each vector carries the schema's verdict and the one this reader must give; the two differ
// only where the vector names a documented difference. It is read in place, never copied.
const configVectors = "../../../conformance/fixtures/gateway_config_vectors.json"

func TestGatewayConfigAgreesWithTheSchemaVectors(t *testing.T) {
	data, err := os.ReadFile(configVectors)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Differences map[string]string `json:"differences"`
		Vectors     []struct {
			Name       string          `json:"name"`
			Schema     string          `json:"schema"`
			Go         string          `json:"go"`
			Difference *string         `json:"difference"`
			Config     json.RawMessage `json:"config"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) < 100 {
		t.Fatalf("only %d vectors", len(file.Vectors))
	}
	for _, v := range file.Vectors {
		if (v.Go == v.Schema) != (v.Difference == nil) {
			t.Fatalf("%s: schema %s, go %s, difference %v", v.Name, v.Schema, v.Go, v.Difference)
		}
		if v.Difference != nil && file.Differences[*v.Difference] == "" {
			t.Fatalf("%s: difference %q is not documented", v.Name, *v.Difference)
		}
		_, err := ParseConfig(v.Config)
		switch {
		case v.Go == "accept" && err != nil:
			t.Errorf("%s: refused, want accepted: %v", v.Name, err)
		case v.Go == "refuse" && err == nil:
			t.Errorf("%s: accepted, want refused (schema: %s)", v.Name, v.Schema)
		case v.Go != "accept" && v.Go != "refuse":
			t.Fatalf("%s: go verdict %q", v.Name, v.Go)
		}
	}
}
