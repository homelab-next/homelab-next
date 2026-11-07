// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGatewayKeyThrottle(t *testing.T) {
	f := newFixture(t) // local-b: 3 requests per 60 s
	for i := 1; i <= 3; i++ {
		if r := f.chat(localKey, "chat-b"); r.status != 200 {
			t.Fatalf("call %d: %d", i, r.status)
		}
		f.clock.Advance(10 * time.Second)
	}
	r := f.chat(localKey, "chat-b")
	typ, code := r.errCode(t)
	if r.status != 429 || typ != "rate_limit_error" || code != "rate_limited" {
		t.Fatalf("call 4: %d %s", r.status, r.body)
	}
	// the first call was at t0, now is t0+30s: it leaves the window in 30 s
	if ra, _ := strconv.Atoi(r.header.Get("Retry-After")); ra != 30 {
		t.Fatalf("Retry-After %q", r.header.Get("Retry-After"))
	}
	// a 429 consumes nothing: after the first call's expiry exactly one more is served
	for i := 0; i < 5; i++ {
		f.chat(localKey, "chat-b")
	}
	f.clock.Advance(30 * time.Second)
	if r := f.chat(localKey, "chat-b"); r.status != 200 {
		t.Fatalf("after the window slid: %d", r.status)
	}
	if r := f.chat(localKey, "chat-b"); r.status != 429 {
		t.Fatalf("the window holds two older calls and this one: %d", r.status)
	}
	if n := len(f.up3.calls()); n != 4 {
		t.Fatalf("upstream served %d, want 4", n)
	}
}

func TestGatewayRoleLimitAcrossDeploymentsAndKeys(t *testing.T) {
	f := newFixture(t, func(cfg map[string]any) {
		roleOf(cfg, "chat-a")["limits"] = map[string]any{"window_s": 60, "max_requests": 2, "max_tokens": nil, "max_cost": nil}
	})
	f.up1.set(status(503)) // every call goes on to chat-a-2: one budget, not per deployment
	for _, key := range []string{agentKey, adminKey} {
		if r := f.chat(key, "chat-a"); r.status != 200 {
			t.Fatalf("%d %s", r.status, r.body)
		}
	}
	r := f.chat(agentKey, "chat-a")
	if _, code := r.errCode(t); r.status != 429 || code != "rate_limited" {
		t.Fatalf("third: %d %s", r.status, r.body)
	}
	if n := len(f.up2.calls()); n != 2 {
		t.Fatalf("chat-a-2 calls %d", n)
	}
}

func TestGatewayTokenLimitRefusesTheNextRequest(t *testing.T) {
	f := newFixture(t, func(cfg map[string]any) {
		k := cfg["keys"].([]any)[1].(map[string]any)
		k["limits"] = map[string]any{"window_s": 60, "max_requests": nil, "max_tokens": 70}
	})
	// each call reserves max_tokens 10 plus its input (about 18 tokens of body) and spends the
	// 12 its reply reports: the window then holds 12, 24, 36, 48, 60 ...
	body := chatBody("chat-b", "max_tokens", 10)
	n := 0
	for ; n < 10; n++ {
		if r := f.do("POST", "/v1/chat/completions", localKey, body); r.status != 200 {
			break
		}
	}
	// 12*n + reservation (10+in) must stay <= 70: with in about 18, three calls fit, the fourth not
	in := estimateTokens(len(mustJSON(body)))
	want := 0
	for 12*want+10+in <= 70 {
		want++
	}
	if n != want {
		t.Fatalf("%d calls served, want %d (input estimate %d)", n, want, in)
	}
	f.clock.Advance(61 * time.Second)
	if r := f.do("POST", "/v1/chat/completions", localKey, body); r.status != 200 {
		t.Fatalf("after expiry: %d", r.status)
	}
}

func TestGatewayTokenLimitIsACeiling(t *testing.T) {
	f := newFixture(t, func(cfg map[string]any) {
		k := cfg["keys"].([]any)[1].(map[string]any)
		k["limits"] = map[string]any{"window_s": 60, "max_requests": nil, "max_tokens": 100}
	})
	// a request that may produce more than the whole budget can never be admitted: a 400, not a
	// 429 whose Retry-After would only bring it back
	r := f.do("POST", "/v1/chat/completions", localKey, chatBody("chat-b", "max_tokens", 1000))
	typ, code := r.errCode(t)
	msg := r.json(t)["error"].(map[string]any)["message"].(string)
	if r.status != 400 || typ != "invalid_request_error" || code != "reservation_exceeds_limit" ||
		!strings.Contains(msg, "key's token limit") || r.header.Get("Retry-After") != "" || len(f.up3.calls()) != 0 {
		t.Fatalf("over the ceiling: %d %s", r.status, r.body)
	}
	// without max_tokens the role's max_context_tokens (8192) is reserved: refused too
	if _, code := f.chat(localKey, "chat-b").errCode(t); code != "reservation_exceeds_limit" {
		t.Fatalf("max_context_tokens reservation: %s", code)
	}
	// two calls in flight together cannot both hold their reservation: the second waits for the
	// first to settle (at its real 12 tokens)
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	f.up3.set(func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		entered <- struct{}{}
		<-release
		openAIBackend("ok")(w, r, body)
	})
	body := chatBody("chat-b", "max_tokens", 40) // reserves 40 + about 18
	done := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest("POST", f.gw.URL+"/v1/chat/completions", bytes.NewReader(mustJSON(body)))
		req.Header.Set("Authorization", "Bearer "+localKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- 0
			return
		}
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	<-entered
	if r := f.do("POST", "/v1/chat/completions", localKey, body); r.status != 429 {
		t.Fatalf("second while the first holds its reservation: %d", r.status)
	}
	close(release)
	if st := <-done; st != 200 {
		t.Fatalf("first: %d", st)
	}
	f.waitIdle()
	f.up3.set(openAIBackend("ok"))
	if r := f.do("POST", "/v1/chat/completions", localKey, body); r.status != 200 {
		t.Fatalf("after the first settled at 12 tokens: %d %s", r.status, r.body)
	}
}

func TestGatewayCostLimit(t *testing.T) {
	f := newFixture(t, func(cfg map[string]any) {
		r := roleOf(cfg, "chat-b")
		r["cost_per_1k_tokens"] = 1.0
		r["limits"] = map[string]any{"window_s": 60, "max_requests": nil, "max_tokens": nil, "max_cost": 0.06}
	})
	// a call reserves (10 + about 18 tokens) = 0.028 and spends 12 tokens, costing 0.012: the window
	// holds 0.012, 0.024, 0.036; the fourth would reach 0.064 with its reservation
	body := chatBody("chat-b", "max_tokens", 10)
	in := estimateTokens(len(mustJSON(body)))
	want := 0
	for float64(12*want+10+in)/1000 <= 0.06 {
		want++
	}
	n := 0
	for ; n < 10; n++ {
		if r := f.do("POST", "/v1/chat/completions", agentKey, body); r.status != 200 {
			break
		}
	}
	if n != want {
		t.Fatalf("%d served, want %d", n, want)
	}
	// the window is not empty, but a reservation of 0.118 is over the whole 0.06: a 400
	r := f.do("POST", "/v1/chat/completions", agentKey, chatBody("chat-b", "max_tokens", 100))
	if _, code := r.errCode(t); r.status != 400 || code != "reservation_exceeds_limit" ||
		!strings.Contains(r.json(t)["error"].(map[string]any)["message"].(string), "role chat-b's cost limit") {
		t.Fatalf("a reservation over max_cost: %d %s", r.status, r.body)
	}
	recs := f.records()
	if c, _ := recs[0]["cost_usd"].(float64); c < 0.0119 || c > 0.0121 {
		t.Fatalf("cost_usd %v", recs[0]["cost_usd"])
	}
}

func TestGatewayReplyWithoutUsageIsEstimated(t *testing.T) {
	f := newFixture(t)
	f.up3.set(func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
		writeTestJSON(w, 200, map[string]any{"id": "x", "object": "chat.completion",
			"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": "abcdefghi"}}}})
	})
	body := chatBody("chat-b")
	if r := f.do("POST", "/v1/chat/completions", agentKey, body); r.status != 200 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	rec := f.records()[0]
	in := float64(estimateTokens(len(mustJSON(body))))
	if rec["usage_estimated"] != true || rec["output_tokens"] != 3.0 || rec["input_tokens"] != in {
		t.Fatalf("record %v (input estimate %v)", rec, in)
	}
}

func TestGatewayReservationInputsAreIntegers(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct {
		field, value string
	}{
		{"n", `"2"`}, {"n", `0`}, {"n", `-1`}, {"n", `2.0`}, {"n", `1e1`}, {"n", `true`},
		{"max_tokens", `"64"`}, {"max_tokens", `64.0`}, {"max_tokens", `1e5`}, {"max_tokens", `-5`}, {"max_tokens", `[]`},
		{"max_completion_tokens", `64.5`}, {"max_completion_tokens", `-1`}, {"max_completion_tokens", `99999999999999999999`},
	} {
		body := `{"model":"chat-b","messages":[{"role":"user","content":"x"}],"` + c.field + `":` + c.value + `}`
		r := f.do("POST", "/v1/chat/completions", agentKey, body)
		_, code := r.errCode(t)
		msg := r.json(t)["error"].(map[string]any)["message"].(string)
		if r.status != 400 || code != "invalid_request" || !strings.Contains(msg, c.field) {
			t.Errorf("%s=%s: %d %s", c.field, c.value, r.status, r.body)
		}
	}
	for _, ok := range []string{`"n":1`, `"n":3`, `"max_tokens":0`, `"max_tokens":64`, `"max_completion_tokens":7`, `"max_tokens":null`} {
		body := `{"model":"chat-b","messages":[{"role":"user","content":"x"}],` + ok + `}`
		if r := f.do("POST", "/v1/chat/completions", agentKey, body); r.status != 200 {
			t.Errorf("%s: %d %s", ok, r.status, r.body)
		}
	}
	if n := len(f.up3.calls()); n != 6 {
		t.Fatalf("upstream calls %d, want 6", n)
	}
}

func TestGatewayReservationEstimate(t *testing.T) {
	s := &Server{reserveTokens: 100}
	ctx := 500
	withCtx, noCtx := &Role{MaxContextTokens: &ctx}, &Role{}
	for _, c := range []struct {
		name string
		body map[string]any
		kind string
		role *Role
		want int
	}{
		{"max_tokens", map[string]any{"max_tokens": 50}, "chat", withCtx, 50},
		{"max_completion_tokens", map[string]any{"max_completion_tokens": 60}, "chat", withCtx, 60},
		{"the larger of both", map[string]any{"max_tokens": 70, "max_completion_tokens": 60}, "chat", withCtx, 70},
		{"role context", map[string]any{}, "chat", withCtx, 500},
		{"configured default", map[string]any{}, "chat", noCtx, 100},
		{"times n", map[string]any{"max_tokens": 50, "n": 3}, "chat", withCtx, 150},
		{"embedding is input only", map[string]any{"max_tokens": 50}, "embedding", withCtx, 0},
		{"absurd values saturate", map[string]any{"max_tokens": 1 << 50, "n": 1 << 50}, "chat", withCtx, maxEstimate},
	} {
		raw := map[string]json.RawMessage{}
		for k, v := range c.body {
			raw[k] = mustJSON(v)
		}
		cl := &call{kind: c.kind, body: raw, bodyBytes: 400}
		want := c.want + 100 // 400 body bytes are 100 input tokens
		if c.want == maxEstimate {
			want = maxEstimate
		}
		if got := s.estimate(cl, c.role); got != want {
			t.Errorf("%s: %d, want %d", c.name, got, want)
		}
	}
}

func TestGatewayLimiterUnit(t *testing.T) {
	c := newClock()
	two := 2
	cfg := &Config{Roles: map[string]*Role{"r": {Limits: &RoleLimits{WindowS: 10, MaxRequests: &two}}},
		Keys: []*Key{{Alias: "k", Limits: &KeyLimits{WindowS: 10, MaxRequests: &two}}}}
	l := NewLimiter(cfg, c.Now)
	l.Admit("k", "other", 0)
	l.Admit("", "r", 0)
	l.Admit("", "r", 0)
	// the role is full: the key's request is not counted on the key either
	if _, scope, _, ok := l.Admit("k", "r", 0); ok || scope != "role" {
		t.Fatalf("role: %v %s", ok, scope)
	}
	if _, _, _, ok := l.Admit("k", "other", 0); !ok {
		t.Fatal("the role 429 consumed the key's budget")
	}
	if _, scope, _, ok := l.Admit("k", "r", 0); ok || scope != "key" {
		t.Fatalf("key checked first: %v %s", ok, scope)
	}
	c.Advance(10 * time.Second) // events exactly window old have left
	if _, _, _, ok := l.Admit("k", "r", 0); !ok {
		t.Fatal("window did not expire")
	}
}

func TestGatewayLimiterBucketsAreBounded(t *testing.T) {
	c := newClock()
	big, tok := 1<<30, 1<<30
	cfg := &Config{Roles: map[string]*Role{
		"req": {Limits: &RoleLimits{WindowS: 5, MaxRequests: &big}},
		"tok": {Limits: &RoleLimits{WindowS: 5, MaxTokens: &tok}},
	}}
	l := NewLimiter(cfg, c.Now)
	for i := 0; i < 20000; i++ {
		if i%1000 == 0 {
			c.Advance(time.Second)
		}
		res, _, _, _ := l.Admit("", "req", 10)
		l.Settle(res, "", "req", 10)
		res, _, _, _ = l.Admit("", "tok", 10)
		l.Settle(res, "", "tok", 10)
	}
	rb, tb := l.roles["req"], l.roles["tok"]
	// one bucket per second of the window (5) plus the current one, however many requests
	if len(rb.buckets) > 6 || len(tb.buckets) > 6 {
		t.Fatalf("buckets %d %d", len(rb.buckets), len(tb.buckets))
	}
	// a window without max_requests keeps no request counts; one without max_tokens no tokens
	if tb.requests != 0 || rb.tokens != 0 {
		t.Fatalf("kept what has no max: requests %d tokens %v", tb.requests, rb.tokens)
	}
	if rb.requests != 5000 || tb.tokens != 50000 {
		t.Fatalf("running sums: %d %v", rb.requests, tb.tokens)
	}
	c.Advance(time.Minute)
	l.Admit("", "tok", 0)
	if tb.tokens != 0 || len(tb.buckets) > 1 {
		t.Fatalf("after the window: %v %d", tb.tokens, len(tb.buckets))
	}
}

func TestGatewayDiscardedReplySpendsItsReservation(t *testing.T) {
	for _, c := range []struct {
		name  string
		reply func(http.ResponseWriter, *http.Request, map[string]any)
		want  int
	}{
		{"a malformed 200 (failover, then 502)", func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
			w.Write([]byte("<<not json>>"))
		}, 502},
		{"an over-size 200", func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
			writeTestJSON(w, 200, map[string]any{"pad": strings.Repeat("z", 17<<20)})
		}, 502},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, func(cfg map[string]any) {
				k := cfg["keys"].([]any)[1].(map[string]any)
				k["limits"] = map[string]any{"window_s": 60, "max_requests": nil, "max_tokens": 200}
			})
			f.up3.set(c.reply)
			body := chatBody("chat-b", "max_tokens", 50) // reserves about 70
			// the upstream answered and its reply was thrown away: the call spends what it
			// reserved, so the third call no longer fits (2 x 70 + 70 > 200)
			for i := 0; i < 2; i++ {
				if r := f.do("POST", "/v1/chat/completions", localKey, body); r.status != c.want {
					t.Fatalf("call %d: %d %s", i+1, r.status, r.body)
				}
				f.waitIdle()
			}
			if r := f.do("POST", "/v1/chat/completions", localKey, body); r.status != 429 {
				t.Fatalf("third: %d %s", r.status, r.body)
			}
		})
	}
	// an upstream 5xx is not a discarded reply: it spends nothing
	f := newFixture(t, func(cfg map[string]any) {
		k := cfg["keys"].([]any)[1].(map[string]any)
		k["limits"] = map[string]any{"window_s": 60, "max_requests": nil, "max_tokens": 200}
	})
	f.up3.set(status(503))
	for i := 0; i < 5; i++ {
		if r := f.do("POST", "/v1/chat/completions", localKey, chatBody("chat-b", "max_tokens", 50)); r.status != 502 {
			t.Fatalf("5xx call %d: %d", i+1, r.status)
		}
	}
}
