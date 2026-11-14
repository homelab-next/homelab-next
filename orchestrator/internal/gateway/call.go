// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/gatewaytag"
)

// call is one model request on its way through admission and routing.
type call struct {
	id           string
	start        time.Time
	caller       *caller
	kind         string // chat or embedding
	alias        string // the requested role alias: every reply's model
	role         *Role
	body         map[string]json.RawMessage
	stream       bool
	includeUsage bool
	tlpFields    []string
	tag          *string
	bodyBytes    int          // the request body's size: the input estimate (ADR-0038 R16)
	res          *Reservation // what admission reserved on the limit windows
	refused      bool         // refused at admission (scope, TLP, limit): an aggregated record
	called       bool         // a request was sent to some deployment
	unsupported  *apiError    // the first deployment that could not take the request said why
	urlParts     *string      // urlPart, computed once
	discarded    []spent      // attempts whose 2xx reply the gateway threw away

	// outcome, for the usage record
	status     int
	errorCode  string
	servedRole string
	deployment string
	usage      tokenUsage
	ttft       *time.Duration
	fallbacks  int
	tlp        *TLPRecord
}

// spent is what one discarded attempt is charged.
type spent struct {
	role   string
	tokens int
}

// tokenUsage is what a reply reported (or, estimated, what the gateway counted).
type tokenUsage struct {
	input, output *int
	cacheRead     *int // nil: the upstream reported no cache figure (ADR-0038 d6)
	estimated     bool
}

func (u tokenUsage) total() int {
	n := 0
	if u.input != nil {
		n += *u.input
	}
	if u.output != nil {
		n += *u.output
	}
	return n
}

// modelCall runs the contract's evaluation order (ADR-0038 d4): auth (done by the caller), body and exact
// model (400), key scope (403), TLP (403), key then role limit (429), routing. Every decision
// past the 400 step writes one usage record (ADR-0038 d6).
func (s *Server) modelCall(w http.ResponseWriter, r *http.Request, c *caller, kind string) {
	cl, apiErr := s.parseCall(w, r, c, kind)
	if apiErr != nil {
		apiErr.write(w)
		return
	}
	w.Header().Set("X-Request-Id", cl.id)
	// the reply is complete on the wire before the call is recorded: it never waits on the log
	defer func() {
		_ = http.NewResponseController(w).Flush()
		s.record(cl)
	}()
	if err := s.admit(cl); err != nil {
		cl.status, cl.errorCode, cl.refused = err.status, err.code, true
		err.write(w)
		return
	}
	s.route(w, r, cl)
}

// parseCall is the 400 step: the body is a JSON object whose model names a role of this kind
// byte for byte, stream is a boolean, and X-HNX-Tag (optional, one field) is a tag.
func (s *Server) parseCall(w http.ResponseWriter, r *http.Request, c *caller, kind string) (*call, *apiError) {
	body, size, apiErr := readBody(w, r)
	if apiErr != nil {
		return nil, apiErr
	}
	var model string
	if raw, ok := body["model"]; !ok || json.Unmarshal(raw, &model) != nil || model == "" {
		return nil, badRequest("invalid_request", "the body needs a string model")
	}
	role := s.cfg.Roles[model]
	if role == nil {
		return nil, modelNotFound()
	}
	if role.Kind != kind {
		return nil, badRequest("wrong_model_kind", "role "+model+" is a "+role.Kind+" role, not "+kind)
	}
	cl := &call{id: newRequestID(), start: s.now(), caller: c, kind: kind, alias: model, role: role,
		body: body, bodyBytes: size, tlpFields: r.Header.Values("X-HNX-TLP")}
	if kind == "chat" {
		if raw, ok := body["stream"]; ok && json.Unmarshal(raw, &cl.stream) != nil {
			return nil, badRequest("invalid_request", "stream must be a boolean")
		}
		var opts struct {
			IncludeUsage bool `json:"include_usage"`
		}
		if raw, ok := body["stream_options"]; ok && json.Unmarshal(raw, &opts) == nil {
			cl.includeUsage = opts.IncludeUsage
		}
		// what admission reserves is read from these: anything but a plain integer is refused,
		// never read as 0 or truncated
		for _, f := range []struct {
			name string
			min  int64
		}{{"n", 1}, {"max_tokens", 0}, {"max_completion_tokens", 0}} {
			raw, ok := body[f.name]
			if !ok || string(raw) == "null" {
				continue
			}
			if _, ok := jsonInt(raw, f.min); !ok {
				return nil, badRequest("invalid_request", fmt.Sprintf("%s must be a JSON integer >= %d", f.name, f.min))
			}
		}
	}
	switch tags := r.Header.Values(gatewaytag.Header); {
	case len(tags) > 1:
		return nil, badRequest("invalid_tag", gatewaytag.Header+" is given more than once")
	case len(tags) == 1 && !gatewaytag.Valid(tags[0]):
		return nil, badRequest("invalid_tag", gatewaytag.Header+" is not a gateway tag")
	case len(tags) == 1:
		cl.tag = &tags[0]
	}
	return cl, nil
}

// admit applies scope, TLP and limits, in that order; only a request that passes all of them is
// counted. A TLP refusal of the requested role is final: it never leads to a fallback (ADR-0038 d5).
func (s *Server) admit(cl *call) *apiError {
	c, role := cl.caller, cl.role
	switch {
	case c.kind == callerTelemetry:
		return errNoModel
	case c.kind == callerKey && !c.key.Allows(cl.alias):
		return modelNotAllowed(cl.alias)
	}
	a := s.tlpAdmit(cl, role)
	cl.tlp = &TLPRecord{Label: a.Label.String(), Ceiling: role.ceiling.String(),
		LeavesLab: role.LeavesLab, Allowed: a.Allowed, Reason: a.Reason}
	if !a.Allowed {
		return tlpRefused(cl.alias, a, role.ceiling)
	}
	est := s.estimate(cl, role)
	if scope, limit, over := s.limits.Exceeds(cl.keyAlias(), cl.alias, est); over {
		return reservationTooLarge(scope, limit, cl.alias, est)
	}
	res, scope, after, ok := s.limits.Admit(cl.keyAlias(), cl.alias, est)
	if !ok {
		return rateLimited(scope, after)
	}
	cl.res = res
	return nil
}

// jsonInt reads raw as a JSON integer (digits only: no fraction, no exponent) of at least min
// that fits an int64.
func jsonInt(raw json.RawMessage, min int64) (int64, bool) {
	s := strings.TrimSpace(string(raw))
	digits := strings.TrimPrefix(s, "-")
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return v, err == nil && v >= min
}

// maxEstimate caps one reservation, so that an absurd max_tokens or n cannot overflow.
const maxEstimate = 1 << 40

// estimate is what admission reserves on the token and cost windows for a call to role (ADR-0038 R16):
// the output it may produce (max_completion_tokens or max_tokens, else the role's
// max_context_tokens, else the configured default; times n) plus its input, estimated from the
// body size. An embedding call produces no output tokens: its estimate is its input.
func (s *Server) estimate(cl *call, role *Role) int {
	in := int64(estimateTokens(cl.bodyBytes))
	if cl.kind == "embedding" {
		return int(min(in, maxEstimate))
	}
	var out int64
	for _, f := range []string{"max_completion_tokens", "max_tokens"} {
		var v int64
		if raw, ok := cl.body[f]; ok && json.Unmarshal(raw, &v) == nil && v > out {
			out = v
		}
	}
	if out <= 0 {
		out = int64(s.reserveTokens)
		if role.MaxContextTokens != nil {
			out = int64(*role.MaxContextTokens)
		}
	}
	var n int64 = 1
	if raw, ok := cl.body["n"]; ok && json.Unmarshal(raw, &n) == nil && n > 1 {
		n = min(n, maxEstimate)
	} else {
		n = 1
	}
	out = min(out, maxEstimate)
	if out > (maxEstimate-in)/n {
		return maxEstimate
	}
	return int(out*n + in)
}

// urlPartTypes are content part types that name something a backend fetches.
var urlPartTypes = map[string]bool{"image_url": true, "audio_url": true, "video_url": true}

// urlPart names the first thing in the request body that carries a URL, or "" when there is
// none: a key named url or *_url at any depth (top-level fields, messages in any shape, an
// embedding's input, extra fields alike), or a part of type image_url, audio_url or video_url.
// A local backend could fetch any of them from inside the lab.
func (cl *call) urlPart() string {
	if cl.urlParts != nil {
		return *cl.urlParts
	}
	found := ""
	for _, k := range sortedKeys(cl.body) {
		if k == "url" || strings.HasSuffix(k, "_url") {
			found = k
			break
		}
		var v any
		if json.Unmarshal(cl.body[k], &v) != nil {
			continue
		}
		if found = findURLPart(v); found != "" {
			break
		}
	}
	cl.urlParts = &found
	return found
}

// findURLPart looks through v (a part, or lists of them) for a URL-bearing part.
func findURLPart(v any) string {
	switch v := v.(type) {
	case map[string]any:
		typ, _ := v["type"].(string)
		if urlPartTypes[typ] || hasURLField(v) {
			if typ == "" {
				return "(untyped)"
			}
			return typ
		}
		for _, x := range v {
			if t := findURLPart(x); t != "" {
				return t
			}
		}
	case []any:
		for _, x := range v {
			if t := findURLPart(x); t != "" {
				return t
			}
		}
	}
	return ""
}

func hasURLField(v any) bool {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			if k == "url" || strings.HasSuffix(k, "_url") || hasURLField(x) {
				return true
			}
		}
	case []any:
		for _, x := range v {
			if hasURLField(x) {
				return true
			}
		}
	}
	return false
}

// keyAlias is the limit window's name: "" for the admin key, which has none.
func (cl *call) keyAlias() string {
	if cl.caller.kind == callerKey {
		return cl.caller.key.Alias
	}
	return ""
}

// tlpAdmit judges the call for role (the requested role or a fallback).
func (s *Server) tlpAdmit(cl *call, role *Role) Admission {
	return Admit(role.ceiling, role.LeavesLab, cl.caller.sender(), cl.tlpFields)
}

func readBody(w http.ResponseWriter, r *http.Request) (map[string]json.RawMessage, int, *apiError) {
	if r.ContentLength > MaxBodyBytes {
		return nil, 0, errTooLarge
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		return nil, 0, errTooLarge
	}
	if err != nil {
		return nil, 0, badRequest("invalid_request", "the request body could not be read")
	}
	body, apiErr := decodeBody(data)
	return body, len(data), apiErr
}

// decodeBody reads the body's top-level object key by key. A key given twice is refused (the
// decoder would keep the last silently), and so is a case variant of model or stream, which a
// case-insensitive upstream decoder could read in place of the key the gateway checked.
func decodeBody(data []byte) (map[string]json.RawMessage, *apiError) {
	notObject := badRequest("invalid_json", "the request body is not a JSON object")
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, notObject
	}
	body := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, notObject
		}
		k, _ := kt.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, notObject
		}
		if _, dup := body[k]; dup {
			return nil, badRequest("invalid_json", "the request body gives the key "+strconv.Quote(k)+" twice")
		}
		for _, exact := range []string{"model", "stream"} {
			if k != exact && strings.EqualFold(k, exact) {
				return nil, badRequest("invalid_request", "the request body key "+strconv.Quote(k)+
					" is a case variant of "+exact+": only the exact spelling is read")
			}
		}
		body[k] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, notObject
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, badRequest("invalid_json", "the request body is not one JSON object")
	}
	return body, nil
}

// record settles the call's reservation against the reply's tokens and writes its usage record.
func (s *Server) record(cl *call) {
	var cost *float64
	s.limits.Settle(cl.res, cl.keyAlias(), cl.servedRole, cl.usage.total())
	for _, d := range cl.discarded {
		s.limits.Spend(cl.keyAlias(), d.role, d.tokens)
	}
	if cl.servedRole != "" && cl.status >= 200 && cl.status < 300 {
		// a refused or failed call has no cost (null), not a cost of 0
		total := cl.usage.total()
		if per := s.cfg.Roles[cl.servedRole].CostPer1KTokens; per != nil {
			c := float64(total) * *per / 1000
			if !math.IsNaN(c) {
				cost = &c
			}
		}
	}
	if s.usage == nil {
		return
	}
	rec := UsageRecord{
		TS: cl.start.UTC().Format(time.RFC3339Nano), TurnID: cl.id, GatewayTag: cl.tag,
		Key: cl.caller.alias(), Owner: cl.caller.owner(), ModelRole: cl.alias, Model: cl.alias,
		CallType: cl.kind, Stream: cl.stream, Status: cl.status,
		InputTokens: cl.usage.input, OutputTokens: cl.usage.output,
		CacheReadTokens: cl.usage.cacheRead, CostUSD: cost,
		DurationMS: s.now().Sub(cl.start).Milliseconds(), Fallbacks: cl.fallbacks,
		UsageEstimated: cl.usage.estimated, TLP: cl.tlp, Count: 1,
	}
	if cl.usage.cacheRead != nil {
		hit := *cl.usage.cacheRead > 0
		rec.CacheHit = &hit
	}
	if cl.servedRole != "" {
		rec.ServedRole, rec.Deployment = &cl.servedRole, &cl.deployment
	}
	if cl.errorCode != "" {
		rec.ErrorCode = &cl.errorCode
	}
	if cl.ttft != nil {
		ms := cl.ttft.Milliseconds()
		rec.TTFTMS = &ms
	}
	if cl.refused {
		s.usage.AppendRefusal(rec)
		return
	}
	if err := s.usage.Append(rec); err != nil {
		s.log.Error("usage record not written", "request_id", cl.id, "err", err)
	}
}
