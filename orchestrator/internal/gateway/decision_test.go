// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"strings"
	"testing"
)

// decisionBackend answers like a decision model: it refuses chat and embeddings (501) and
// answers /v1/systemone with one noul per question.
func decisionBackend(w http.ResponseWriter, r *http.Request, body map[string]any) {
	if r.URL.Path != "/v1/systemone" {
		writeTestJSON(w, 501, map[string]any{"error": map[string]any{"message": "decision model", "type": "x"}})
		return
	}
	answers := map[string]any{}
	for id := range body["questions"].(map[string]any) {
		answers[id] = map[string]any{"type": "noul", "noul": 0.75}
	}
	writeTestJSON(w, 200, map[string]any{"answers": answers,
		"usage": map[string]any{"input_tokens": 31, "output_tokens": 2}})
}

func withDecisionRoles(cfg map[string]any) {
	roles := cfg["roles"].(map[string]any)
	up := roleOf(cfg, "chat-b")["deployments"].([]any)[0].(map[string]any)["base_url"].(string)
	roles["decide"] = role("decision", "red", false, []any{dep("decide-1", "openai", "local", up, "decider-backend", nil)}, []any{}, nil)
	roles["decide-cloud"] = role("decision", "green", true, []any{dep("decide-cloud-1", "openai", "cloud", up, "decider-cloud-backend", nil)}, []any{}, nil)
	for _, k := range cfg["keys"].([]any) {
		if key := k.(map[string]any); key["alias"] == "agent-a" {
			key["roles"] = []any{"chat-a", "chat-b", "cloud", "decide", "decide-cloud", "embed"}
		}
	}
}

// withDecisionExtras adds decide-fb (a second decision role, on up2) and decide-limited (one request a minute).
func withDecisionExtras(cfg map[string]any) {
	withDecisionRoles(cfg)
	roles := cfg["roles"].(map[string]any)
	up2 := roleOf(cfg, "chat-a")["deployments"].([]any)[1].(map[string]any)["base_url"].(string)
	up3 := roleOf(cfg, "chat-b")["deployments"].([]any)[0].(map[string]any)["base_url"].(string)
	roles["decide-fb"] = role("decision", "red", false, []any{dep("decide-fb-1", "openai", "local", up2, "decider-fb-backend", nil)}, []any{}, nil)
	roles["decide-limited"] = role("decision", "red", false, []any{dep("decide-limited-1", "openai", "local", up3, "decider-lim-backend", nil)}, []any{},
		map[string]any{"window_s": 60, "max_requests": 1, "max_tokens": nil, "max_cost": nil})
	roleOf(cfg, "decide")["fallbacks"] = []any{"decide-fb"}
	for _, k := range cfg["keys"].([]any) {
		if key := k.(map[string]any); key["alias"] == "agent-a" {
			key["roles"] = []any{"chat-a", "chat-b", "cloud", "decide", "decide-cloud", "decide-fb", "decide-limited", "embed"}
		}
	}
}

func decisionExtrasFixture(t *testing.T) *fixture {
	f := newFixture(t, withDecisionExtras)
	f.up3.set(decisionBackend)
	f.up2.set(decisionBackend)
	return f
}

func TestDecisionRoleLimitIs429(t *testing.T) {
	f := decisionExtrasFixture(t)
	if r := f.do("POST", "/v1/systemone", agentKey, systemoneBody("decide-limited")); r.status != 200 {
		t.Fatalf("first: %d %s", r.status, r.body)
	}
	r := f.do("POST", "/v1/systemone", agentKey, systemoneBody("decide-limited"))
	if typ, code := r.errCode(t); r.status != 429 || typ != "rate_limit_error" || code != "rate_limited" {
		t.Fatalf("second: %d %s", r.status, r.body)
	}
	if n := len(f.up3.calls()); n != 1 {
		t.Fatalf("the refused call reached the backend: %d calls", n)
	}
}

func TestDecisionBodyOverTheCapIs413(t *testing.T) {
	f := decisionFixture(t)
	big := `{"model":"decide","questions":{},"pad":"` + strings.Repeat("x", MaxBodyBytes) + `"}`
	r := f.do("POST", "/v1/systemone", agentKey, big)
	if _, code := r.errCode(t); r.status != 413 || code != "request_too_large" {
		t.Fatalf("%d %s", r.status, r.body)
	}
	if len(f.up3.calls()) != 0 {
		t.Fatal("an oversized body reached the backend")
	}
}

func TestDecisionGarbageUsageFallsBackToTheEstimate(t *testing.T) {
	for name, usage := range map[string]any{
		"a string":        "x",
		"negative input":  map[string]any{"input_tokens": -1, "output_tokens": 2},
		"negative output": map[string]any{"input_tokens": 5, "output_tokens": -9},
		"null":            nil,
		"wrong types":     map[string]any{"input_tokens": "5", "output_tokens": []any{}},
	} {
		f := decisionFixture(t)
		f.up3.set(func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
			writeTestJSON(w, 200, map[string]any{"answers": map[string]any{}, "usage": usage})
		})
		if r := f.do("POST", "/v1/systemone", agentKey, systemoneBody("decide")); r.status != 200 {
			t.Fatalf("%s: %d %s", name, r.status, r.body)
		}
		rec := f.records()[0]
		in, _ := rec["input_tokens"].(float64)
		out, _ := rec["output_tokens"].(float64)
		if name == "negative output" {
			// a sane input is kept and the bad output counted as none
			if in != 5 || out != 0 {
				t.Errorf("%s: record %v", name, rec)
			}
			continue
		}
		if rec["usage_estimated"] != true || in <= 0 || out < 0 {
			t.Errorf("%s: record %v", name, rec)
		}
	}
}

func TestDecisionFallsBackToAnotherDecisionRole(t *testing.T) {
	f := decisionExtrasFixture(t)
	f.up3.set(status(500)) // decide's own backend fails
	r := f.do("POST", "/v1/systemone", agentKey, systemoneBody("decide"))
	if r.status != 200 || r.header.Get(HeaderAttemptedFallbacks) != "1" {
		t.Fatalf("%d %v %s", r.status, r.header, r.body)
	}
	if got := f.up2.calls(); len(got) != 1 || got[0].path != "/v1/systemone" || got[0].body["model"] != "decider-fb-backend" {
		t.Fatalf("fallback call: %v", got)
	}
	rec := f.records()[0]
	if rec["served_role"] != "decide-fb" || rec["model_role"] != "decide" || rec["fallbacks"] != float64(1) {
		t.Fatalf("record: %v", rec)
	}
}

func decisionFixture(t *testing.T) *fixture {
	f := newFixture(t, withDecisionRoles)
	f.up3.set(decisionBackend)
	return f
}

func systemoneBody(model string) map[string]any {
	return map[string]any{"model": model, "state": map[string]any{"k": "v"},
		"questions": map[string]any{"q1": map[string]any{"type": "noul", "instructions": "Does this answer it?"}}}
}

func TestDecisionForwardsAndRecords(t *testing.T) {
	f := decisionFixture(t)
	r := f.do("POST", "/v1/systemone", agentKey, systemoneBody("decide"), "X-HNX-Tag", "judge-1")
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	got := f.up3.calls()[0]
	if got.path != "/v1/systemone" || got.body["model"] != "decider-backend" || strings.Contains(string(got.raw), `"decide"`) {
		t.Fatalf("forwarded %s %s", got.path, got.raw)
	}
	if got.body["state"] == nil {
		t.Fatalf("state was not forwarded: %s", got.raw)
	}
	ans := r.json(t)["answers"].(map[string]any)["q1"].(map[string]any)
	if ans["type"] != "noul" || ans["noul"] != 0.75 {
		t.Fatalf("answer changed: %s", r.body)
	}
	recs := f.records()
	if len(recs) != 1 {
		t.Fatalf("records: %v", recs)
	}
	rec := recs[0]
	if rec["call_type"] != "decision" || rec["model_role"] != "decide" || rec["input_tokens"] != float64(31) ||
		rec["key"] != "agent-a" || rec["gateway_tag"] != "judge-1" {
		t.Fatalf("record: %v", rec)
	}
}

func TestDecisionKindIsEnforced(t *testing.T) {
	f := decisionFixture(t)
	for _, c := range []struct {
		name, path string
		body       any
	}{
		{"chat on a decision role", "/v1/chat/completions", chatBody("decide")},
		{"embeddings on a decision role", "/v1/embeddings", map[string]any{"model": "decide", "input": "x"}},
		{"systemone on a chat role", "/v1/systemone", systemoneBody("chat-a")},
		{"systemone on an embedding role", "/v1/systemone", systemoneBody("embed")},
	} {
		r := f.do("POST", c.path, agentKey, c.body)
		if _, code := r.errCode(t); r.status != 400 || code != "wrong_model_kind" {
			t.Errorf("%s: %d %s", c.name, r.status, r.body)
		}
	}
	for name, body := range map[string]any{
		"no questions":      map[string]any{"model": "decide"},
		"questions a list":  map[string]any{"model": "decide", "questions": []any{}},
		"questions a null":  map[string]any{"model": "decide", "questions": nil},
		"not a JSON object": "[]",
	} {
		if r := f.do("POST", "/v1/systemone", agentKey, body); r.status != 400 {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	if r := f.do("POST", "/v1/systemone", "", systemoneBody("decide")); r.status != 401 {
		t.Errorf("no key: %d", r.status)
	}
	if r := f.do("POST", "/v1/systemone", localKey, systemoneBody("decide")); r.status != 403 {
		t.Errorf("key without the role: %d", r.status)
	}
	if len(f.up3.calls()) != 0 {
		t.Fatalf("a refused call reached the backend: %v", f.up3.calls())
	}
}

func TestDecisionSharesChatAdmission(t *testing.T) {
	f := decisionFixture(t)
	// a role that leaves the lab follows the chat rules: a label above green is refused, clear passes
	if r := f.do("POST", "/v1/systemone", agentKey, systemoneBody("decide-cloud"), "X-HNX-TLP", "amber"); r.status != 403 {
		t.Errorf("amber to a cloud decision role: %d %s", r.status, r.body)
	}
	if r := f.do("POST", "/v1/systemone", agentKey, systemoneBody("decide-cloud")); r.status != 403 {
		t.Errorf("unlabelled to a cloud decision role: %d %s", r.status, r.body)
	}
	if r := f.do("POST", "/v1/systemone", agentKey, systemoneBody("decide-cloud"), "X-HNX-TLP", "clear"); r.status != 200 {
		t.Errorf("clear to a cloud decision role: %d %s", r.status, r.body)
	}
	// a local-only decision role takes red and never leaves
	if r := f.do("POST", "/v1/systemone", agentKey, systemoneBody("decide"), "X-HNX-TLP", "red"); r.status != 200 {
		t.Errorf("red to a local decision role: %d %s", r.status, r.body)
	}
}

func TestDecisionBackendFailureAndBadReply(t *testing.T) {
	f := decisionFixture(t)
	f.up3.set(func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
		writeTestJSON(w, 200, map[string]any{"nope": 1})
	})
	if r := f.do("POST", "/v1/systemone", agentKey, systemoneBody("decide")); r.status != 502 {
		t.Fatalf("a reply with no answers: %d %s", r.status, r.body)
	}
	// no usage in the reply: estimated from the request
	f.up3.set(func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
		writeTestJSON(w, 200, map[string]any{"answers": map[string]any{}})
	})
	if r := f.do("POST", "/v1/systemone", agentKey, systemoneBody("decide")); r.status != 200 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	recs := f.records()
	if last := recs[len(recs)-1]; last["usage_estimated"] != true || last["input_tokens"] == nil {
		t.Fatalf("estimated usage: %v", last)
	}
}

func TestDecisionConfigRules(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"anthropic deployment": func(c map[string]any) {
			withDecisionRoles(c)
			depOf(c, "decide", 0)["protocol"] = "anthropic"
		},
		"chat fallback": func(c map[string]any) {
			withDecisionRoles(c)
			roleOf(c, "decide")["fallbacks"] = []any{"chat-b"}
		},
	} {
		cfg := validConfig()
		edit(cfg)
		if _, err := ParseConfig(mustJSON(cfg)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
