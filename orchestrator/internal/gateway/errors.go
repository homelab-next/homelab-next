// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// apiError is an OpenAI error envelope plus its HTTP status.
type apiError struct {
	status     int
	message    string
	typ        string
	code       string
	retryAfter time.Duration
}

func (e *apiError) write(w http.ResponseWriter) {
	if e.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retrySeconds(e.retryAfter)))
	}
	writeJSON(w, e.status, map[string]any{
		"error": map[string]any{"message": e.message, "type": e.typ, "code": e.code},
	})
}

func retrySeconds(d time.Duration) int {
	s := int((d + time.Second - 1) / time.Second)
	if s < 1 {
		s = 1
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		status, body = http.StatusInternalServerError, []byte(`{"error":{"message":"internal error","type":"server_error","code":"internal_error"}}`)
	}
	writeRaw(w, status, body)
}

func writeRaw(w http.ResponseWriter, status int, body []byte) { writeParts(w, status, body) }

// writeParts writes a JSON reply given in pieces, without joining them.
func writeParts(w http.ResponseWriter, status int, parts ...[]byte) {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", strconv.Itoa(n))
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	for _, p := range parts {
		if _, err := w.Write(p); err != nil {
			return
		}
	}
}

var (
	errAuth = &apiError{status: 401, message: "invalid or missing API key",
		typ: "authentication_error", code: "invalid_api_key"}
	errNotFound = &apiError{status: 404, message: "no such route",
		typ: "invalid_request_error", code: "not_found"}
	errTooLarge = &apiError{status: 413, message: "request body over 8 MiB",
		typ: "invalid_request_error", code: "request_too_large"}
	errRoute = &apiError{status: 403, message: "this key may not call this route",
		typ: "permission_error", code: "route_not_allowed"}
	errNoModel = &apiError{status: 403, message: "this key may call no model",
		typ: "permission_error", code: "model_not_allowed"}
	errOverloaded = &apiError{status: 503, message: "the gateway is holding too many replies; retry shortly",
		typ: "server_error", code: "overloaded", retryAfter: time.Second}
	errConcurrency = &apiError{status: 429, message: "too many calls in flight",
		typ: "rate_limit_error", code: "concurrency_limited", retryAfter: time.Second}
)

func badRequest(code, message string) *apiError {
	return &apiError{status: 400, message: message, typ: "invalid_request_error", code: code}
}

func modelNotFound() *apiError {
	return badRequest("model_not_found", "the model is not a role this gateway serves")
}

func modelNotAllowed(role string) *apiError {
	return &apiError{status: 403, message: "this key may not call role " + role,
		typ: "permission_error", code: "model_not_allowed"}
}

func rateLimited(scope string, after time.Duration) *apiError {
	return &apiError{status: 429, message: "rate limit reached for this " + scope,
		typ: "rate_limit_error", code: "rate_limited", retryAfter: after}
}

// reservationTooLarge is a call whose reservation alone is larger than a token or cost max: it can
// never be admitted, so it is a 400 rather than a 429 with a Retry-After. It names the call's own
// reservation and which limit, never another key's numbers.
func reservationTooLarge(scope, limit, role string, tokens int) *apiError {
	which := "this key's " + limit + " limit"
	if scope == "role" {
		which = "role " + role + "'s " + limit + " limit"
	}
	return badRequest("reservation_exceeds_limit", fmt.Sprintf("this call reserves %d tokens, more than %s "+
		"allows in a whole window: send a smaller max_tokens (or n)", tokens, which))
}

func upstreamExhausted(credsRefused bool) *apiError {
	if credsRefused {
		return &apiError{status: 502, message: "upstream refused the gateway's credentials",
			typ: "upstream_error", code: "upstream_auth_failed"}
	}
	return &apiError{status: 502, message: "every deployment of the role and its fallbacks failed",
		typ: "upstream_error", code: "upstream_unavailable"}
}

// upstreamRejected is an upstream 4xx (not 401, 403 or 429): its status with the gateway's own
// envelope, never the upstream body (R6).
func upstreamRejected(status int) *apiError {
	return &apiError{status: status, message: "upstream rejected the request (status " + strconv.Itoa(status) + ")",
		typ: "invalid_request_error", code: "upstream_rejected"}
}

func tlpRefused(role string, a Admission, ceiling Label) *apiError {
	var msg string
	if a.Reason == ReasonUnlabelled {
		msg = "tlp refused (unlabelled): the request carries no X-HNX-TLP label, is read as red, " +
			"and red is above the ceiling " + ceiling.String() + " of role " + role
	} else {
		msg = "tlp refused (above-ceiling): the request is judged at " + a.Label.String() +
			", above the ceiling " + ceiling.String() + " of role " + role
	}
	return &apiError{status: 403, message: msg, typ: "permission_error", code: "tlp_refused"}
}
