// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"strings"
	"testing"

	"github.com/homelab-next/homelab-next/orchestrator/internal/gatewaytag"
)

func TestGatewayTag(t *testing.T) {
	for _, c := range []struct{ prefix, run, want string }{
		{"", "run-1", "run-1"},
		{"job:", "run-1", "job:run-1"},
		{"site/a.", "01J:x_y-2", "site/a.01J:x_y-2"},
	} {
		got, err := GatewayTag(c.prefix, c.run)
		if err != nil || got != c.want || !gatewaytag.Valid(got) {
			t.Errorf("GatewayTag(%q, %q) = %q, %v; want %q", c.prefix, c.run, got, err, c.want)
		}
	}
	for _, c := range []struct{ prefix, run string }{
		{"a,b", "run-1"},                   // the prefix has a comma
		{"has space", "run-1"},             // or a space
		{strings.Repeat("p", 65), "run-1"}, // or is too long
		{"", ""},                           // no run id
		{"", "a/b"},                        // a run id with "/" would not split back off the prefix
		{"", "run\n"},                      // a line break
		{"", strings.Repeat("r", 129)},     // a run id past the record's bound
		{"job:", "run-1,forged"},           // a second tag smuggled in
	} {
		if got, err := GatewayTag(c.prefix, c.run); err == nil {
			t.Errorf("GatewayTag(%q, %q) = %q, want an error", c.prefix, c.run, got)
		}
	}
	if ValidateGatewayTagPrefix("") != nil || ValidateGatewayTagPrefix("job:") != nil || ValidateGatewayTagPrefix("x\n") == nil {
		t.Error("ValidateGatewayTagPrefix")
	}
}
