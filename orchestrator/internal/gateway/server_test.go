// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var storeWords = regexp.MustCompile(`(?i)no connected db|database|prisma|\bdb\b|store|internal server error`)

func TestGatewayAuthRejects(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct{ name, header string }{
		{"no key", ""}, {"wrong key", "Bearer sk-bf-fake-not-a-key-0000"}, {"not bearer", "Basic " + agentKey},
		{"empty bearer", "Bearer "},
	} {
		for _, path := range []string{"/v1/chat/completions", "/v1/models", "/v1/usage", "/v1/embeddings"} {
			method := "POST"
			if path == "/v1/models" || path == "/v1/usage" {
				method = "GET"
			}
			var r reply
			if c.header == "" {
				r = f.do(method, path, "", chatBody("chat-a"))
			} else {
				r = f.do(method, path, "", chatBody("chat-a"), "Authorization", c.header)
			}
			if r.status != 401 {
				t.Fatalf("%s %s: %d", c.name, path, r.status)
			}
			want := `{"error":{"code":"invalid_api_key","message":"invalid or missing API key","type":"authentication_error"}}`
			if string(r.body) != want {
				t.Fatalf("%s: body %s", c.name, r.body)
			}
			if storeWords.MatchString(string(r.body)) {
				t.Fatalf("401 names a store: %s", r.body)
			}
		}
	}
	if len(f.up1.calls()) != 0 || len(f.records()) != 0 {
		t.Fatal("an unauthenticated call reached an upstream or the usage log")
	}
}

func TestGatewayModelsPerKey(t *testing.T) {
	f := newFixture(t)
	want := map[string][]string{
		adminKey: {"chat-a", "chat-b", "cloud", "embed"},
		agentKey: {"chat-a", "chat-b", "cloud", "embed"},
		localKey: {"chat-b"},
	}
	for key, ids := range want {
		r := f.do("GET", "/v1/models", key, nil)
		var raw map[string]any
		_ = json.Unmarshal(r.body, &raw)
		data := []any{}
		for _, id := range ids {
			data = append(data, map[string]any{"id": id, "object": "model", "owned_by": "hnx"})
		}
		if r.status != 200 || !reflect.DeepEqual(raw, map[string]any{"object": "list", "data": data}) {
			t.Fatalf("%s: %d %s", key[:5], r.status, r.body)
		}
	}
	r := f.do("GET", "/v1/models", telemetryKey, nil)
	if typ, code := r.errCode(t); r.status != 403 || typ != "permission_error" || code != "route_not_allowed" {
		t.Fatalf("telemetry /v1/models: %d %s", r.status, r.body)
	}
}

func TestGatewayModelErrors(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name   string
		key    string
		path   string
		body   any
		status int
		typ    string
		code   string
	}{
		{"unknown model", agentKey, "/v1/chat/completions", chatBody("no-such-model-zz"), 400, "invalid_request_error", "model_not_found"},
		{"case folded is unknown", agentKey, "/v1/chat/completions", chatBody("CHAT-A"), 400, "invalid_request_error", "model_not_found"},
		{"mdl prefix is unknown", agentKey, "/v1/chat/completions", chatBody("mdl:chat-a"), 400, "invalid_request_error", "model_not_found"},
		{"padded is unknown", agentKey, "/v1/chat/completions", chatBody(" chat-a"), 400, "invalid_request_error", "model_not_found"},
		{"backend id is unknown", agentKey, "/v1/chat/completions", chatBody("backend-a1"), 400, "invalid_request_error", "model_not_found"},
		{"outside the key", localKey, "/v1/chat/completions", chatBody("chat-a"), 403, "permission_error", "model_not_allowed"},
		{"telemetry calls no model", telemetryKey, "/v1/chat/completions", chatBody("chat-a"), 403, "permission_error", "model_not_allowed"},
		{"chat role on embeddings", agentKey, "/v1/embeddings", map[string]any{"model": "chat-a", "input": "x"}, 400, "invalid_request_error", "wrong_model_kind"},
		{"embedding role on chat", agentKey, "/v1/chat/completions", chatBody("embed"), 400, "invalid_request_error", "wrong_model_kind"},
		{"not JSON", agentKey, "/v1/chat/completions", "{nope", 400, "invalid_request_error", "invalid_json"},
		{"two objects", agentKey, "/v1/chat/completions", `{"model":"chat-a"}{}`, 400, "invalid_request_error", "invalid_json"},
		{"array", agentKey, "/v1/chat/completions", `[]`, 400, "invalid_request_error", "invalid_json"},
		{"no model", agentKey, "/v1/chat/completions", map[string]any{"messages": []any{}}, 400, "invalid_request_error", "invalid_request"},
		{"model not a string", agentKey, "/v1/chat/completions", map[string]any{"model": 3}, 400, "invalid_request_error", "invalid_request"},
		{"model twice", agentKey, "/v1/chat/completions", `{"model":"chat-b","model":"chat-a","messages":[]}`, 400, "invalid_request_error", "invalid_json"},
		{"Model beside model", agentKey, "/v1/chat/completions", `{"model":"chat-b","Model":"chat-a","messages":[]}`, 400, "invalid_request_error", "invalid_request"},
		{"MODEL only", agentKey, "/v1/chat/completions", `{"MODEL":"chat-b","messages":[]}`, 400, "invalid_request_error", "invalid_request"},
		{"Stream beside stream", agentKey, "/v1/chat/completions", `{"model":"chat-b","stream":false,"Stream":true,"messages":[]}`, 400, "invalid_request_error", "invalid_request"},
		{"long-s stream", agentKey, "/v1/chat/completions", "{\"model\":\"chat-b\",\"\u017ftream\":true,\"messages\":[]}", 400, "invalid_request_error", "invalid_request"},
		{"stream twice", agentKey, "/v1/chat/completions", `{"model":"chat-b","stream":true,"stream":false,"messages":[]}`, 400, "invalid_request_error", "invalid_json"},
		{"stream not a boolean", agentKey, "/v1/chat/completions", chatBody("chat-a", "stream", "yes"), 400, "invalid_request_error", "invalid_request"},
	}
	for _, c := range cases {
		r := f.do("POST", c.path, c.key, c.body)
		typ, code := r.errCode(t)
		if r.status != c.status || typ != c.typ || code != c.code {
			t.Errorf("%s: %d %s", c.name, r.status, r.body)
		}
	}
	if n := len(f.up1.calls()) + len(f.up3.calls()); n != 0 {
		t.Fatalf("a refused call reached an upstream (%d)", n)
	}
}

func TestGatewayNoSubstitution(t *testing.T) {
	// a key asking for a role outside its scope is refused, never served by a role it may call
	f := newFixture(t)
	r := f.chat(localKey, "chat-a")
	if r.status != 403 || len(f.up1.calls())+len(f.up2.calls())+len(f.up3.calls()) != 0 {
		t.Fatalf("%d, upstream calls %d/%d/%d", r.status, len(f.up1.calls()), len(f.up2.calls()), len(f.up3.calls()))
	}
}

func TestGatewayRoutesAndLimits(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/healthz", 200}, {"POST", "/healthz", 404}, {"GET", "/v1/chat/completions", 404},
		{"POST", "/v1/completions", 404}, {"GET", "/", 404}, {"GET", "/v1/models/chat-a", 404},
		{"DELETE", "/v1/models", 404},
	} {
		r := f.do(c.method, c.path, agentKey, nil)
		if r.status != c.status {
			t.Errorf("%s %s: %d", c.method, c.path, r.status)
		}
	}
	if r := f.do("GET", "/healthz", "", nil); string(r.body) != `{"replies_overloaded":0,"status":"ok","usage_lines_skipped":0,"usage_records_dropped":0}` {
		t.Fatalf("healthz: %s", r.body)
	}
	big := `{"model":"chat-a","pad":"` + strings.Repeat("x", MaxBodyBytes) + `"}`
	r := f.do("POST", "/v1/chat/completions", agentKey, big)
	if _, code := r.errCode(t); r.status != 413 || code != "request_too_large" {
		t.Fatalf("8 MiB: %d %s", r.status, r.body)
	}
}

func TestGatewayEvaluationOrder(t *testing.T) {
	// R4: scope (403) before TLP (403 tlp_refused) before limits; refused requests consume nothing
	f := newFixture(t, func(cfg map[string]any) {
		roleOf(cfg, "cloud")["limits"] = map[string]any{"window_s": 60, "max_requests": 1, "max_tokens": nil, "max_cost": nil}
	})
	if _, code := f.chat(localKey, "cloud").errCode(t); code != "model_not_allowed" {
		t.Fatalf("scope first: %s", code)
	}
	for i := 0; i < 3; i++ {
		if _, code := f.chat(agentKey, "cloud").errCode(t); code != "tlp_refused" {
			t.Fatalf("tlp: %s", code)
		}
	}
	if r := f.chat(agentKey, "cloud", "X-HNX-TLP", "clear"); r.status != 200 {
		t.Fatalf("the TLP refusals consumed the role's one request: %d %s", r.status, r.body)
	}
	if r := f.chat(agentKey, "cloud", "X-HNX-TLP", "clear"); r.status != 429 {
		t.Fatalf("second: %d", r.status)
	}
}

func TestGatewayTLPRefusal(t *testing.T) {
	f := newFixture(t)
	r := f.chat(agentKey, "cloud")
	typ, code := r.errCode(t)
	msg := r.json(t)["error"].(map[string]any)["message"].(string)
	if r.status != 403 || typ != "permission_error" || code != "tlp_refused" || !strings.Contains(msg, "unlabelled") || !strings.Contains(msg, "green") {
		t.Fatalf("unlabelled: %d %s", r.status, r.body)
	}
	r = f.chat(agentKey, "cloud", "X-HNX-TLP", "amber")
	msg = r.json(t)["error"].(map[string]any)["message"].(string)
	if r.status != 403 || !strings.Contains(msg, "above-ceiling") || !strings.Contains(msg, "amber") {
		t.Fatalf("amber: %d %s", r.status, r.body)
	}
	if r := f.chat(agentKey, "cloud", "X-HNX-TLP", "clear", "X-HNX-TLP", "clear"); r.status != 403 {
		t.Fatalf("two fields: %d", r.status)
	}
	if r := f.chat(agentKey, "cloud", "X-HNX-TLP", "TLP:CLEAR"); r.status != 200 {
		t.Fatalf("clear: %d %s", r.status, r.body)
	}
	// R1: the admin key's sending ceiling is red, so it never reaches a green cloud role
	if r := f.chat(adminKey, "cloud", "X-HNX-TLP", "clear"); r.status != 403 {
		t.Fatalf("admin on cloud: %d %s", r.status, r.body)
	}
	if len(f.anth.calls()) != 1 {
		t.Fatalf("anthropic calls: %d", len(f.anth.calls()))
	}
}

func TestGatewayTagHeader(t *testing.T) {
	f := newFixture(t)
	for _, good := range []string{"run-1", "Agent.Job:42", "team/agent-a", "a"} {
		if r := f.chat(agentKey, "chat-b", "X-HNX-Tag", good); r.status != 200 {
			t.Errorf("tag %q: %d", good, r.status)
		}
	}
	for _, bad := range []string{"", "has space", "ends/", "a,b", strings.Repeat("a", 200)} {
		r := f.chat(agentKey, "chat-b", "X-HNX-Tag", bad)
		if _, code := r.errCode(t); r.status != 400 || code != "invalid_tag" {
			t.Errorf("tag %q: %d %s", bad, r.status, r.body)
		}
	}
	if r := f.chat(agentKey, "chat-b", "X-HNX-Tag", "a", "X-HNX-Tag", "b"); r.status != 400 {
		t.Errorf("two tag fields: %d", r.status)
	}
	for _, c := range f.up3.calls() {
		for h := range c.header {
			if strings.HasPrefix(strings.ToLower(h), "x-hnx") {
				t.Fatalf("forwarded %s", h)
			}
		}
	}
}

func TestGatewayUpstreamRequestIsOwnHeadersAndReencodedBody(t *testing.T) {
	f := newFixture(t)
	body := `{"model":"chat-b","messages":[{"role":"user","content":"hi"}],"temperature":0,"x_extra":{"k":[1,2]}}`
	r := f.do("POST", "/v1/chat/completions", agentKey, body, "Cookie", "c=1", "X-HNX-TLP", "red",
		"X-Forwarded-For", "192.0.2.10", "Anthropic-Version", "bogus")
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	got := f.up3.calls()[0]
	for h := range got.header {
		switch h {
		case "Content-Type", "Accept", "Content-Length", "Accept-Encoding":
		case "User-Agent":
			if got.header.Get(h) != "hnx-gateway" {
				t.Errorf("User-Agent %q", got.header.Get(h))
			}
		default:
			t.Errorf("upstream got header %s", h)
		}
	}
	if got.body["model"] != "backend-b1" || got.body["temperature"] != 0.0 || got.body["x_extra"] == nil {
		t.Fatalf("body %v", got.body)
	}
	if strings.Contains(string(got.raw), "chat-b") {
		t.Fatalf("the alias was forwarded: %s", got.raw)
	}
}

func TestGatewayReplyModelIsAlias(t *testing.T) {
	f := newFixture(t)
	r := f.chat(agentKey, "chat-a")
	if r.status != 200 || r.json(t)["model"] != "chat-a" || strings.Contains(string(r.body), "backend") {
		t.Fatalf("%d %s", r.status, r.body)
	}
	e := f.do("POST", "/v1/embeddings", agentKey, map[string]any{"model": "embed", "input": "alpha"})
	if e.status != 200 || e.json(t)["model"] != "embed" || f.up3.calls()[0].path != "/v1/embeddings" {
		t.Fatalf("embeddings: %d %s", e.status, e.body)
	}
}
