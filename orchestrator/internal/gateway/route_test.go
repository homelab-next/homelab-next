// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGatewayFailoverOrderAndEligibility(t *testing.T) {
	for _, c := range []struct {
		name   string
		first  func(http.ResponseWriter, *http.Request, map[string]any)
		served string // which upstream answers: "1" or "2"
		status int
		code   string
	}{
		{"503 moves on", status(503), "2", 200, ""},
		{"500 moves on", status(500), "2", 200, ""},
		{"429 moves on", status(429), "2", 200, ""},
		{"401 moves on", status(401), "2", 200, ""},
		{"403 moves on", status(403), "2", 200, ""},
		{"302 moves on, never followed", func(w http.ResponseWriter, r *http.Request, _ map[string]any) {
			http.Redirect(w, r, "http://198.51.100.1/steal", http.StatusFound)
		}, "2", 200, ""},
		{"malformed 200 moves on", func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
			w.Write([]byte("<<not json>>"))
		}, "2", 200, ""},
		{"400 is returned", status(400), "1", 400, "upstream_rejected"},
		{"404 is returned", status(404), "1", 404, "upstream_rejected"},
		{"healthy first serves", openAIBackend("one"), "1", 200, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.up1.set(c.first)
			r := f.chat(agentKey, "chat-a")
			if r.status != c.status {
				t.Fatalf("%d %s", r.status, r.body)
			}
			n1, n2 := len(f.up1.calls()), len(f.up2.calls())
			if n1 != 1 || (c.served == "2") != (n2 == 1) || len(f.up3.calls()) != 0 {
				t.Fatalf("calls %d %d %d", n1, n2, len(f.up3.calls()))
			}
			if c.code != "" {
				typ, code := r.errCode(t)
				want := "upstream rejected the request (status "
				if typ != "invalid_request_error" || code != c.code || !strings.Contains(string(r.body), want) ||
					strings.Contains(string(r.body), "secret-internal-detail") || strings.Contains(string(r.body), "backend-a1") {
					t.Fatalf("4xx body %s", r.body)
				}
			}
			if r.header.Get(HeaderAttemptedFallbacks) != "" {
				t.Fatal("fallback header without a fallback")
			}
		})
	}
}

func TestGatewayConnectionErrorAndTimeoutMoveOn(t *testing.T) {
	f := newFixture(t, func(cfg map[string]any) {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := ln.Addr().String()
		ln.Close() // nothing listens there now
		deps := roleOf(cfg, "chat-a")["deployments"].([]any)
		deps[0].(map[string]any)["base_url"] = "http://" + addr
	})
	if r := f.chat(agentKey, "chat-a"); r.status != 200 || len(f.up2.calls()) != 1 {
		t.Fatalf("connection refused: %d", r.status)
	}
	f2 := newFixture(t)
	f2.up1.set(func(w http.ResponseWriter, r *http.Request, _ map[string]any) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	start := time.Now()
	if r := f2.chat(agentKey, "chat-a"); r.status != 200 || len(f2.up2.calls()) != 1 {
		t.Fatalf("timeout: %d", r.status)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("the per-attempt timeout did not apply")
	}
}

func TestGatewayFallbackRole(t *testing.T) {
	f := newFixture(t)
	f.up1.set(status(503))
	f.up2.set(status(502))
	r := f.chat(agentKey, "chat-a")
	if r.status != 200 || r.header.Get(HeaderAttemptedFallbacks) != "1" || r.json(t)["model"] != "chat-a" {
		t.Fatalf("%d %v %s", r.status, r.header, r.body)
	}
	if len(f.up3.calls()) != 1 || f.up3.calls()[0].body["model"] != "backend-b1" {
		t.Fatal("chat-b did not serve")
	}
	rec := f.records()[0]
	if rec["model_role"] != "chat-a" || rec["served_role"] != "chat-b" || rec["deployment"] != "chat-b-1" || rec["fallbacks"] != 1.0 {
		t.Fatalf("record %v", rec)
	}
	// a fallback that answers an upstream 4xx did not serve: no header, and the 400 has no cost
	f.up3.set(status(400))
	r = f.chat(agentKey, "chat-a")
	if r.status != 400 || r.header.Get(HeaderAttemptedFallbacks) != "" {
		t.Fatalf("fallback 4xx: %d %v", r.status, r.header)
	}
	f.up3.set(status(500))
	r = f.chat(agentKey, "chat-a")
	typ, code := r.errCode(t)
	if r.status != 502 || typ != "upstream_error" || code != "upstream_unavailable" || r.header.Get(HeaderAttemptedFallbacks) != "" {
		t.Fatalf("exhausted: %d %s", r.status, r.body)
	}
}

func TestGatewayUpstreamAuthRefusalIs502(t *testing.T) {
	f := newFixture(t)
	f.up1.set(status(401))
	f.up2.set(status(403))
	f.up3.set(status(503))
	r := f.chat(agentKey, "chat-a")
	if typ, _ := r.errCode(t); r.status != 502 || typ != "upstream_error" ||
		!strings.Contains(string(r.body), "upstream refused the gateway's credentials") {
		t.Fatalf("%d %s", r.status, r.body)
	}
}

func TestGatewayFallbackIsTLPAdmittedAndLimited(t *testing.T) {
	// chat-a (green) falls back to a clear cloud role; a request labelled green skips it (ADR-0038 d5),
	// chat-b is skipped by its limit (one request a window, spent first), and the caller gets 502
	edit := func(cfg map[string]any) {
		roles := cfg["roles"].(map[string]any)
		roles["chat-a"].(map[string]any)["leaves_lab"] = true
		roles["chat-a"].(map[string]any)["tlp_ceiling"] = "green"
		roles["chat-a"].(map[string]any)["fallbacks"] = []any{"cloud", "chat-b"}
		roles["cloud"].(map[string]any)["tlp_ceiling"] = "clear"
		roles["chat-b"].(map[string]any)["limits"] = map[string]any{"window_s": 60, "max_requests": 1, "max_tokens": nil, "max_cost": nil}
		cfg["keys"].([]any)[0].(map[string]any)["tlp_ceiling"] = "clear"
	}
	f := newFixture(t, edit)
	if r := f.chat(agentKey, "chat-b"); r.status != 200 || len(f.up3.calls()) != 1 {
		t.Fatalf("chat-b: %d %s", r.status, r.body)
	}
	f.up1.set(status(503))
	f.up2.set(status(503))
	r := f.chat(agentKey, "chat-a", "X-HNX-TLP", "green")
	if r.status != 502 || len(f.anth.calls()) != 0 || len(f.up3.calls()) != 1 {
		t.Fatalf("green: %d, cloud %d, chat-b %d", r.status, len(f.anth.calls()), len(f.up3.calls()))
	}
	r = f.chat(agentKey, "chat-a", "X-HNX-TLP", "clear")
	if r.status != 200 || len(f.anth.calls()) != 1 || r.header.Get(HeaderAttemptedFallbacks) != "1" {
		t.Fatalf("clear: %d %s", r.status, r.body)
	}
}

func TestGatewayStreamRewritesEveryChunk(t *testing.T) {
	f := newFixture(t)
	r := f.do("POST", "/v1/chat/completions", agentKey, chatBody("chat-a", "stream", true))
	if r.status != 200 || !strings.HasPrefix(r.header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("%d %s", r.status, r.body)
	}
	data := sseData(r.body)
	if data[len(data)-1] != "[DONE]" {
		t.Fatalf("no [DONE]: %q", data)
	}
	text := ""
	for _, d := range data[:len(data)-1] {
		var m map[string]any
		if err := jsonUnmarshal(d, &m); err != nil || m["model"] != "chat-a" {
			t.Fatalf("chunk %s", d)
		}
		if _, has := m["usage"]; has {
			t.Fatalf("the usage chunk the caller did not ask for was forwarded: %s", d)
		}
		text += deltaText(m)
	}
	if strings.TrimSpace(text) != "hello from one" || strings.Contains(string(r.body), "backend") {
		t.Fatalf("text %q body %s", text, r.body)
	}
	up := f.up1.calls()[0].body
	if up["stream_options"].(map[string]any)["include_usage"] != true {
		t.Fatalf("include_usage not set upstream: %v", up)
	}
	rec := f.records()[0]
	if rec["stream"] != true || rec["input_tokens"] != 5.0 || rec["output_tokens"] != 7.0 || rec["usage_estimated"] != false || rec["ttft_ms"] == nil {
		t.Fatalf("record %v", rec)
	}
	// the caller asked for usage: the usage chunk is forwarded
	r = f.do("POST", "/v1/chat/completions", agentKey, chatBody("chat-a", "stream", true,
		"stream_options", map[string]any{"include_usage": true}))
	if !strings.Contains(string(r.body), `"total_tokens":12`) {
		t.Fatalf("usage chunk missing: %s", r.body)
	}
}

func TestGatewayStreamUsageEstimate(t *testing.T) {
	f := newFixture(t)
	f.up1.set(func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"abcdefghi\"}}]}\n\ndata: [DONE]\n\n"))
	})
	body := chatBody("chat-a", "stream", true)
	f.do("POST", "/v1/chat/completions", agentKey, body)
	rec := f.records()[0]
	in := float64(estimateTokens(len(mustJSON(body))))
	if rec["usage_estimated"] != true || rec["output_tokens"] != 3.0 || rec["input_tokens"] != in {
		t.Fatalf("record %v", rec)
	}
}

func TestGatewayStreamFailoverBeforeFirstByteOnly(t *testing.T) {
	f := newFixture(t)
	// the first deployment answers 200 SSE then dies before any chunk: the next one serves
	f.up1.set(func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte(": keepalive\n\n"))
	})
	r := f.do("POST", "/v1/chat/completions", agentKey, chatBody("chat-a", "stream", true))
	if r.status != 200 || len(f.up2.calls()) != 1 || !strings.Contains(string(r.body), "two") {
		t.Fatalf("before first byte: %d %s", r.status, r.body)
	}
	// after a chunk was sent, a broken stream ends the reply: no failover, no second backend's text
	f2 := newFixture(t)
	f2.up1.set(func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}\n\ndata: <<garbage>>\n\n"))
	})
	r = f2.do("POST", "/v1/chat/completions", agentKey, chatBody("chat-a", "stream", true))
	if r.status != 200 || len(f2.up2.calls()) != 0 || !strings.Contains(string(r.body), "partial") || strings.Contains(string(r.body), "garbage") {
		t.Fatalf("after first byte: %d calls %d %s", r.status, len(f2.up2.calls()), r.body)
	}
}

func TestGatewayStreamNonSSEAndErrorChunkFailOver(t *testing.T) {
	for _, c := range []struct {
		name  string
		first func(http.ResponseWriter, *http.Request, map[string]any)
	}{
		{"a JSON 200 to a stream request", openAIBackendNoStream("json from one")},
		{"an error chunk first", func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Write([]byte("data: {\"error\":{\"message\":\"overloaded\",\"type\":\"server_error\"}}\n\ndata: [DONE]\n\n"))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.up1.set(c.first)
			r := f.do("POST", "/v1/chat/completions", agentKey, chatBody("chat-a", "stream", true))
			if r.status != 200 || !strings.HasPrefix(r.header.Get("Content-Type"), "text/event-stream") ||
				len(f.up2.calls()) != 1 || !strings.Contains(string(r.body), "two") || strings.Contains(string(r.body), "overloaded") {
				t.Fatalf("%d %s calls %d %s", r.status, r.header.Get("Content-Type"), len(f.up2.calls()), r.body)
			}
			if rec := f.records()[0]; rec["deployment"] != "chat-a-2" {
				t.Fatalf("record %v", rec)
			}
		})
	}
}

// openAIBackendNoStream answers every chat call with a JSON chat.completion, stream or not.
func openAIBackendNoStream(reply string) func(http.ResponseWriter, *http.Request, map[string]any) {
	return func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		delete(body, "stream")
		openAIBackend(reply)(w, r, body)
	}
}
