// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"fmt"

	"github.com/homelab-next/homelab-next/orchestrator/internal/gatewaytag"
)

// ValidateGatewayTagPrefix reports whether prefix may start a job's gateway tag (the controller
// config's events.gateway_tag_prefix): at most 64 of [A-Za-z0-9._:/-], so no comma or space.
func ValidateGatewayTagPrefix(prefix string) error {
	if !gatewaytag.ValidPrefix(prefix) {
		return fmt.Errorf("gateway_tag_prefix %q: want at most 64 of [A-Za-z0-9._:/-]", prefix)
	}
	return nil
}

// GatewayTag is the tag a job's model requests carry (runner.Session.GatewayTag): prefix, then the
// run id. The run id must be one the job record can carry (gatewaytag.RunIDPattern, no "/"), so
// the tag always splits back into the configured prefix and the run, and the result is always a
// tag the gateway accepts.
func GatewayTag(prefix, runID string) (string, error) {
	if err := ValidateGatewayTagPrefix(prefix); err != nil {
		return "", err
	}
	if !gatewaytag.ValidRunID(runID) {
		return "", fmt.Errorf("gateway tag: run id %q is not a run id (%s)", clip(runID), gatewaytag.RunIDPattern)
	}
	tag := prefix + runID
	if !gatewaytag.Valid(tag) {
		return "", fmt.Errorf("gateway tag %q is not a gateway tag", clip(tag))
	}
	return tag, nil
}

// clip bounds a caller's string echoed into an error.
func clip(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
