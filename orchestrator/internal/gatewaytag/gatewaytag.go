// SPDX-License-Identifier: Apache-2.0

// Package gatewaytag is the one definition of the gateway tag, which both sides of the gateway
// share: the controller stamps it on every model request of a job (package inference) and the
// gateway reads it into each usage record (package gateway), so a job's spend joins its
// agent.job.finished record by gateway_tag. Standard library only, like the gateway.
package gatewaytag

import "regexp"

// Header is the request header that carries the tag (ADR-0038 decision 6).
const Header = "X-HNX-Tag"

// Pattern is a tag: an optional prefix of up to 64 characters, then a run id. It is the
// gateway_tag pattern of schemas/events/agent.job.finished.schema.json (a test holds them equal);
// RunIDPattern is that schema's run_id.
const (
	Pattern      = `^[A-Za-z0-9._:/-]{0,64}[A-Za-z0-9._:-]{1,128}$`
	RunIDPattern = `^[A-Za-z0-9._:-]{1,128}$`
	// PrefixPattern is a prefix a site may configure: no comma, no space, nothing a header value
	// cannot carry.
	PrefixPattern = `^[A-Za-z0-9._:/-]{0,64}$`
)

var (
	tagRE    = regexp.MustCompile(Pattern)
	runIDRE  = regexp.MustCompile(RunIDPattern)
	prefixRE = regexp.MustCompile(PrefixPattern)
)

// Valid reports whether tag is a gateway tag.
func Valid(tag string) bool { return tagRE.MatchString(tag) }

// ValidRunID reports whether id can end a tag.
func ValidRunID(id string) bool { return runIDRE.MatchString(id) }

// ValidPrefix reports whether prefix can start a tag.
func ValidPrefix(prefix string) bool { return prefixRE.MatchString(prefix) }
