// SPDX-License-Identifier: Apache-2.0

// The review's probe cases: each line ending in // N is one spelling of a decision on text.
package cases

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"
	str "strings"
)

var known = map[string]bool{"x": true}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

type R struct{ Response, Stderr string }

func f(err error, r R) bool {
	if fmt.Sprint(err) == "connection refused" {
		return true
	} // 1 Sprint compared
	switch fmt.Sprintf("%v", err) {
	case "x":
		return true
	} // 2 switch on Sprintf
	if contains(err.Error(), "refused") {
		return true
	} // 3 through helper (the helper's own line hits? s is param)
	if known[err.Error()] {
		return true
	} // 4 map keyed by text
	if slices.Contains([]string{"x"}, err.Error()) {
		return true
	} // 5 slices.Contains
	var ue *url.Error
	if errors.As(err, &ue) && ue.Op == "Get" {
		return true
	} // 6 errors.As field
	if ok, _ := path.Match("*refused*", err.Error()); ok {
		return true
	} // 7 path.Match
	if strings.Contains(r.Response, "Cannot compress") {
		return true
	} // 8 model output text
	var n int
	fmt.Sscanf(err.Error(), "HTTP %d", &n) // 9 Sscanf
	if err.Error() > "m" {
		return true
	} // 10 ordering
	msg := err.Error()
	if strings.HasPrefix(msg, "x") {
		return true
	} // 11 variable (documented)
	if str.Contains(err.Error(), "x") {
		return true
	} // 12 alias (should hit)
	if strings.Contains(fmt.Sprint(err), "x") {
		return true
	} // 13 (should hit)
	if errors.Is(err, errors.New(err.Error())) {
		return true
	} // 14 errors.New of text
	if strings.EqualFold(fmt.Errorf("w: %w", err).Error(), "x") {
		return true
	} // 15 should hit
	return false
}
