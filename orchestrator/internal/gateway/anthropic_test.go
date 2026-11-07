// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestGatewayAnthropicRequestTranslation(t *testing.T) {
	f := newFixture(t)
	body := map[string]any{"model": "cloud", "temperature": 0.2, "stop": "END", "user": "u1",
		"messages": []any{
			map[string]any{"role": "system", "content": "Be brief."},
			map[string]any{"role": "developer", "content": []any{map[string]any{"type": "text", "text": "No lists."}}},
			map[string]any{"role": "user", "content": "one"},
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": "two"}}},
			map[string]any{"role": "assistant", "content": "ok"},
			map[string]any{"role": "user", "content": "three"},
		}}
	r := f.do("POST", "/v1/chat/completions", agentKey, body, "X-HNX-TLP", "clear")
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	got := f.anth.calls()[0]
	if got.path != "/v1/messages" || got.header.Get("x-api-key") != upstreamKey ||
		got.header.Get("anthropic-version") != "2023-06-01" || got.header.Get("Authorization") != "" {
		t.Fatalf("request %s %v", got.path, got.header)
	}
	want := map[string]any{"model": "claude-backend", "system": "Be brief.\n\nNo lists.", "max_tokens": 1024.0,
		"temperature": 0.2, "stop_sequences": []any{"END"},
		"messages": []any{
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": "one"}, map[string]any{"type": "text", "text": "two"}}},
			map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "text", "text": "ok"}}},
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": "three"}}},
		}}
	if !reflect.DeepEqual(got.body, want) {
		t.Fatalf("translated %s", got.raw)
	}
	r = f.do("POST", "/v1/chat/completions", agentKey, chatBody("cloud", "max_tokens", 77), "X-HNX-TLP", "clear")
	if f.anth.calls()[1].body["max_tokens"] != 77.0 {
		t.Fatalf("max_tokens %v", f.anth.calls()[1].body)
	}
	for _, bad := range []map[string]any{chatBody("cloud", "tools", []any{map[string]any{}}), chatBody("cloud", "n", 2),
		{"model": "cloud", "messages": []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "image_url"}}}}}} {
		r := f.do("POST", "/v1/chat/completions", agentKey, bad, "X-HNX-TLP", "clear")
		if _, code := r.errCode(t); r.status != 400 || code != "unsupported_parameter" {
			t.Fatalf("unsupported: %d %s", r.status, r.body)
		}
	}
}

func TestGatewayAnthropicReplyTranslation(t *testing.T) {
	f := newFixture(t)
	r := f.chat(agentKey, "cloud", "X-HNX-TLP", "clear")
	m := r.json(t)
	ch := m["choices"].([]any)[0].(map[string]any)
	if m["object"] != "chat.completion" || m["model"] != "cloud" || ch["finish_reason"] != "length" ||
		ch["message"].(map[string]any)["content"] != "hello from claude" {
		t.Fatalf("%s", r.body)
	}
	u := m["usage"].(map[string]any)
	if u["prompt_tokens"] != 12.0 || u["completion_tokens"] != 4.0 || u["total_tokens"] != 16.0 {
		t.Fatalf("usage %v", u)
	}
	if strings.Contains(string(r.body), "claude-backend") {
		t.Fatal("backend id leaked")
	}
	rec := f.records()[0]
	if rec["cache_read_tokens"] != 3.0 || rec["cache_hit"] != true {
		t.Fatalf("cache %v", rec)
	}
}

func TestGatewayAnthropicStreamTranslation(t *testing.T) {
	f := newFixture(t)
	r := f.do("POST", "/v1/chat/completions", agentKey, chatBody("cloud", "stream", true,
		"stream_options", map[string]any{"include_usage": true}), "X-HNX-TLP", "clear")
	if r.status != 200 || f.anth.calls()[0].body["stream"] != true {
		t.Fatalf("%d %s", r.status, r.body)
	}
	data := sseData(r.body)
	if data[len(data)-1] != "[DONE]" {
		t.Fatalf("%q", data)
	}
	text, finish, sawUsage := "", "", false
	for i, d := range data[:len(data)-1] {
		var m map[string]any
		if err := json.Unmarshal([]byte(d), &m); err != nil || m["model"] != "cloud" || m["object"] != "chat.completion.chunk" {
			t.Fatalf("chunk %s", d)
		}
		if i == 0 && m["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)["role"] != "assistant" {
			t.Fatalf("first chunk %s", d)
		}
		text += deltaText(m)
		for _, c := range m["choices"].([]any) {
			if fr, ok := c.(map[string]any)["finish_reason"].(string); ok {
				finish = fr
			}
		}
		if u, ok := m["usage"].(map[string]any); ok && u["completion_tokens"] == 4.0 && u["prompt_tokens"] == 9.0 {
			sawUsage = true
		}
	}
	if strings.TrimSpace(text) != "hello from claude" || finish != "stop" || !sawUsage {
		t.Fatalf("text %q finish %q usage %v: %s", text, finish, sawUsage, r.body)
	}
	rec := f.records()[0]
	if rec["output_tokens"] != 4.0 || rec["input_tokens"] != 9.0 || rec["cache_read_tokens"] != nil || rec["cache_hit"] != nil {
		t.Fatalf("record %v", rec)
	}
}

func TestGatewayTranslationRefusalMovesToTheNextDeployment(t *testing.T) {
	// a role served by an anthropic deployment and then an openai one: a request the translation
	// cannot carry goes to the openai deployment
	f := newFixture(t, func(cfg map[string]any) {
		deps := roleOf(cfg, "cloud")["deployments"].([]any)
		roleOf(cfg, "cloud")["deployments"] = append(deps, dep("cloud-2", "openai", "cloud",
			cfg["roles"].(map[string]any)["chat-a"].(map[string]any)["deployments"].([]any)[0].(map[string]any)["base_url"].(string),
			"gpt-backend", "HNX_SECRET_PROVIDER"))
	})
	r := f.do("POST", "/v1/chat/completions", agentKey, chatBody("cloud", "tools", []any{map[string]any{"type": "function"}}),
		"X-HNX-TLP", "clear")
	if r.status != 200 || len(f.anth.calls()) != 0 || len(f.up1.calls()) != 1 || r.json(t)["model"] != "cloud" {
		t.Fatalf("%d %s, anthropic %d openai %d", r.status, r.body, len(f.anth.calls()), len(f.up1.calls()))
	}
	if rec := f.records()[0]; rec["deployment"] != "cloud-2" || rec["status"] != 200.0 {
		t.Fatalf("record %v", rec)
	}
}

func TestGatewayTranslationRefusalWithNoOtherDeploymentIs400(t *testing.T) {
	f := newFixture(t)
	r := f.do("POST", "/v1/chat/completions", agentKey, chatBody("cloud", "tools", []any{map[string]any{}}), "X-HNX-TLP", "clear")
	if _, code := r.errCode(t); r.status != 400 || code != "unsupported_parameter" || len(f.anth.calls()) != 0 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	rec := f.records()[0]
	if rec["deployment"] != nil || rec["served_role"] != nil || rec["status"] != 400.0 || rec["error_code"] != "unsupported_parameter" {
		t.Fatalf("record %v", rec)
	}
}

func TestGatewayURLPartsAreRefusedOnLocalDeployments(t *testing.T) {
	part := func(p map[string]any) map[string]any {
		return map[string]any{"model": "chat-b", "messages": []any{map[string]any{"role": "user",
			"content": []any{map[string]any{"type": "text", "text": "look"}, p}}}}
	}
	f := newFixture(t)
	for _, c := range []struct {
		name string
		part map[string]any
	}{
		{"image_url", map[string]any{"type": "image_url", "image_url": map[string]any{"url": "http://192.0.2.254/latest"}}},
		{"image_url data", map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64,AAAA"}}},
		{"audio_url", map[string]any{"type": "audio_url", "audio_url": map[string]any{"url": "http://192.0.2.10/a.wav"}}},
		{"video_url", map[string]any{"type": "video_url", "video_url": "http://192.0.2.10/v.mp4"}},
		{"input_file url", map[string]any{"type": "input_file", "file_url": "http://192.0.2.10/f.pdf"}},
		{"file with a nested url", map[string]any{"type": "file", "file": map[string]any{"file_url": "file:///etc/passwd"}}},
	} {
		r := f.do("POST", "/v1/chat/completions", agentKey, part(c.part))
		if _, code := r.errCode(t); r.status != 400 || code != "unsupported_parameter" {
			t.Errorf("%s: %d %s", c.name, r.status, r.body)
		}
	}
	if n := len(f.up3.calls()); n != 0 {
		t.Fatalf("a URL part reached a local backend (%d calls)", n)
	}
	// a content value that is a single object is a part too
	single := map[string]any{"model": "chat-b", "messages": []any{map[string]any{"role": "user",
		"content": map[string]any{"type": "image_url", "image_url": map[string]any{"url": "http://192.0.2.10/i.png"}}}}}
	if r := f.do("POST", "/v1/chat/completions", agentKey, single); r.status != 400 {
		t.Errorf("single-object content: %d %s", r.status, r.body)
	}
	// embeddings: input parts (a list, or a single object) and messages content
	for name, body := range map[string]map[string]any{
		"input list":   {"model": "embed", "input": []any{"text", map[string]any{"type": "image_url", "image_url": map[string]any{"url": "http://192.0.2.10/i.png"}}}},
		"input object": {"model": "embed", "input": map[string]any{"type": "input_file", "file_url": "http://192.0.2.10/f.pdf"}},
		"messages": {"model": "embed", "messages": []any{map[string]any{"role": "user",
			"content": []any{map[string]any{"type": "video_url", "video_url": "http://192.0.2.10/v.mp4"}}}}},
	} {
		r := f.do("POST", "/v1/embeddings", agentKey, body)
		if _, code := r.errCode(t); r.status != 400 || code != "unsupported_parameter" {
			t.Errorf("embedding %s: %d %s", name, r.status, r.body)
		}
	}
	if n := len(f.up3.calls()); n != 0 {
		t.Fatalf("a URL part reached a local backend (%d calls)", n)
	}
	// a URL-bearing key anywhere in the body: a top-level messages object, or a top-level field
	for name, body := range map[string]map[string]any{
		"messages object": {"model": "chat-b", "messages": map[string]any{"role": "user",
			"content": map[string]any{"type": "text", "image": map[string]any{"url": "http://192.0.2.10/i.png"}}}},
		"top-level field": {"model": "chat-b", "messages": []any{map[string]any{"role": "user", "content": "x"}},
			"callback_url": "http://192.0.2.10/hook"},
		"deep field": {"model": "chat-b", "messages": []any{map[string]any{"role": "user", "content": "x"}},
			"extra": map[string]any{"a": []any{map[string]any{"b": map[string]any{"url": "http://192.0.2.10/"}}}}},
	} {
		r := f.do("POST", "/v1/chat/completions", agentKey, body)
		if _, code := r.errCode(t); r.status != 400 || code != "unsupported_parameter" {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	if n := len(f.up3.calls()); n != 0 {
		t.Fatalf("a URL key reached a local backend (%d calls)", n)
	}
	if r := f.do("POST", "/v1/embeddings", agentKey, map[string]any{"model": "embed", "input": []any{"a", "b"}}); r.status != 200 {
		t.Errorf("text embedding: %d %s", r.status, r.body)
	}
	// text parts and data that is not a URL part are passed through
	if r := f.do("POST", "/v1/chat/completions", agentKey, part(map[string]any{"type": "input_audio",
		"input_audio": map[string]any{"data": "AAAA", "format": "wav"}})); r.status != 200 {
		t.Fatalf("input_audio: %d %s", r.status, r.body)
	}
}
