// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

// stalledClient sends a chat request on a raw connection with a small receive buffer and then
// never reads: the gateway's writes to it block once the socket buffers are full.
func stalledClient(t *testing.T, f *fixture, body any) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(f.gw.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.(*net.TCPConn).SetReadBuffer(4096)
	data := mustJSON(body)
	fmt.Fprintf(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: gw\r\nAuthorization: Bearer %s\r\n"+
		"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", agentKey, len(data), data)
	return conn
}

func TestGatewayWriteDeadlineEndsAStalledStream(t *testing.T) {
	f := newFixtureOpts(t, func(o *Options) { o.WriteTimeout = 200 * time.Millisecond })
	chunk := mustJSON(map[string]any{"choices": []any{map[string]any{"index": 0,
		"delta": map[string]any{"content": strings.Repeat("x", 64<<10)}}}})
	f.up1.set(func(w http.ResponseWriter, r *http.Request, _ map[string]any) {
		w.Header().Set("Content-Type", "text/event-stream")
		for r.Context().Err() == nil { // an endless stream
			if _, err := fmt.Fprintf(w, "data: %s\n\n", chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	})
	stalledClient(t, f, chatBody("chat-a", "stream", true))
	time.Sleep(100 * time.Millisecond) // the request is in
	f.waitIdle()                       // fatal after 10 s: without a write deadline it never ends
	recs := f.records()
	if len(recs) != 1 || recs[0]["stream"] != true || recs[0]["status"] != 200.0 {
		t.Fatalf("records %v", recs)
	}
}

func TestGatewayWriteDeadlineEndsAStalledReply(t *testing.T) {
	f := newFixtureOpts(t, func(o *Options) { o.WriteTimeout = 200 * time.Millisecond })
	big := strings.Repeat("y", 15<<20) // more than the socket buffers hold
	f.up1.set(func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
		writeTestJSON(w, 200, map[string]any{"object": "chat.completion",
			"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": big}}},
			"usage":   map[string]any{"prompt_tokens": 1, "completion_tokens": 1}})
	})
	stalledClient(t, f, chatBody("chat-a"))
	time.Sleep(100 * time.Millisecond)
	f.waitIdle()
	if recs := f.records(); len(recs) != 1 || recs[0]["status"] != 200.0 {
		t.Fatalf("records %v", recs)
	}
}

func TestGatewayReplyCap(t *testing.T) {
	f := newFixture(t)
	big := strings.Repeat("z", 17<<20) // over the 16 MiB cap
	f.up1.set(func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
		writeTestJSON(w, 200, map[string]any{"object": "chat.completion", "pad": big,
			"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": "one"}}}})
	})
	r := f.chat(agentKey, "chat-a")
	if r.status != 200 || len(f.up2.calls()) != 1 || !strings.Contains(string(r.body), "hello from two") {
		t.Fatalf("an over-cap reply was not a failed attempt: %d, chat-a-2 calls %d", r.status, len(f.up2.calls()))
	}
}

// discardWriter is a ResponseWriter that keeps nothing.
type discardWriter struct{ h http.Header }

func (d *discardWriter) Header() http.Header         { return d.h }
func (d *discardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (d *discardWriter) WriteHeader(int)             {}

func TestGatewayReplyRewriteDoesNotCopyTheReply(t *testing.T) {
	content := strings.Repeat("c", 8<<20)
	data := mustJSON(map[string]any{"model": "backend-x", "object": "chat.completion",
		"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": content}}},
		"usage":   map[string]any{"prompt_tokens": 1, "completion_tokens": 2}})
	cl := &call{alias: "chat-a"}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	res := relayOpenAIReply(&discardWriter{h: http.Header{}}, data, cl)
	runtime.ReadMemStats(&after)
	if !res.answered || *res.usage.output != 2 {
		t.Fatalf("result %+v", res)
	}
	// decoding into a map and re-encoding allocated at least two more copies (16 MiB)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 1<<20 {
		t.Fatalf("the rewrite allocated %d bytes for an 8 MiB reply", alloc)
	}
}

func TestGatewayReplyRewriteCases(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"plain", `{"model":"b","x":1}`, `{"model":"a","x":1}`},
		{"spaced", ` { "x" : [1,{"model":"inner"}] , "model" : "b" } `, ` { "x" : [1,{"model":"inner"}] , "model" : "a" } `},
		{"escaped key", `{"model":"b","y":"}"}`, `{"model":"a","y":"}"}`},
		{"twice", `{"model":"b","model":"c"}`, `{"model":"a","model":"a"}`},
		{"absent", `{"x":"\"model\""}`, `{"model":"a","x":"\"model\""}`},
		{"absent, empty", `{ }`, `{"model":"a" }`},
		{"string with brackets", `{"s":"[{\"","model":null}`, `{"s":"[{\"","model":"a"}`},
	} {
		w := &recordWriter{h: http.Header{}}
		res := relayOpenAIReply(w, []byte(c.in), &call{alias: "a"})
		if !res.answered || w.body.String() != c.want {
			t.Errorf("%s: %q", c.name, w.body.String())
		}
		if w.h.Get("Content-Length") != fmt.Sprint(len(c.want)) {
			t.Errorf("%s: Content-Length %s", c.name, w.h.Get("Content-Length"))
		}
	}
	for _, bad := range []string{`[]`, `{"a":}`, `"x"`, `{"a":1}x`} {
		if res := relayOpenAIReply(&discardWriter{h: http.Header{}}, []byte(bad), &call{alias: "a"}); res.answered {
			t.Errorf("%q answered", bad)
		}
	}
}

type recordWriter struct {
	h    http.Header
	body strings.Builder
}

func (d *recordWriter) Header() http.Header         { return d.h }
func (d *recordWriter) Write(p []byte) (int, error) { return d.body.Write(p) }
func (d *recordWriter) WriteHeader(int)             {}

func TestGatewayInFlightCaps(t *testing.T) {
	block := func(f *fixture, up *upstream) (release func(), entered chan struct{}) {
		gate, in := make(chan struct{}), make(chan struct{}, 4)
		up.set(func(w http.ResponseWriter, r *http.Request, body map[string]any) {
			in <- struct{}{}
			<-gate
			openAIBackend("ok")(w, r, body)
		})
		return func() { close(gate) }, in
	}
	start := func(f *fixture, key, model string) chan int {
		done := make(chan int, 1)
		go func() {
			req, _ := http.NewRequest("POST", f.gw.URL+"/v1/chat/completions", strings.NewReader(string(mustJSON(chatBody(model)))))
			req.Header.Set("Authorization", "Bearer "+key)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				done <- 0
				return
			}
			resp.Body.Close()
			done <- resp.StatusCode
		}()
		return done
	}

	// global cap 1: a second call, from any key, is refused while one runs; it consumes nothing
	f := newFixtureOpts(t, func(o *Options) { o.MaxInFlight = 1 })
	release, in := block(f, f.up3)
	first := start(f, agentKey, "chat-b")
	<-in
	r := f.chat(localKey, "chat-b")
	if typ, code := r.errCode(t); r.status != 429 || typ != "rate_limit_error" || code != "concurrency_limited" || r.header.Get("Retry-After") != "1" {
		t.Fatalf("over the global cap: %d %s", r.status, r.body)
	}
	release()
	if st := <-first; st != 200 {
		t.Fatalf("first: %d", st)
	}
	f.waitIdle()
	f.up3.set(openAIBackend("ok"))
	for i := 0; i < 3; i++ { // local-b may make 3 calls a minute: the refusal took none
		if r := f.chat(localKey, "chat-b"); r.status != 200 {
			t.Fatalf("local-b call %d: %d", i+1, r.status)
		}
	}

	// per-key cap 1: the same key is refused, another key is served
	f = newFixtureOpts(t, func(o *Options) { o.MaxInFlightPerKey = 1 })
	release, in = block(f, f.up1)
	first = start(f, agentKey, "chat-a")
	<-in
	if _, code := f.chat(agentKey, "chat-b").errCode(t); code != "concurrency_limited" {
		t.Fatalf("same key: %s", code)
	}
	if r := f.chat(localKey, "chat-b"); r.status != 200 {
		t.Fatalf("other key: %d", r.status)
	}
	release()
	if st := <-first; st != 200 {
		t.Fatalf("first: %d", st)
	}
}

func TestGatewayReplyReadIsPresizedAndCapped(t *testing.T) {
	big := newReplyBudget(1<<40, 1<<40).taker("k")
	body := strings.Repeat("a", 300<<10)
	// a known Content-Length: one buffer of exactly that size, never grown
	data, over, held, err := readCapped(strings.NewReader(body), int64(len(body)), 1<<20, big)
	if err != nil || over || string(data) != body || cap(data) != len(body) || held != int64(len(body)) {
		t.Fatalf("with a length: cap %d held %d over %v err %v", cap(data), held, over, err)
	}
	// unknown length: grows by doubling, never past the cap
	data, over, held, err = readCapped(strings.NewReader(body), -1, 1<<20, big)
	if err != nil || over || string(data) != body || cap(data) > 1<<20 || held != int64(cap(data)) {
		t.Fatalf("no length: cap %d held %d", cap(data), held)
	}
	// over the cap: reported, and the buffer is the cap, not more
	data, over, _, err = readCapped(strings.NewReader(strings.Repeat("b", 2<<20)), -1, 1<<20, big)
	if err != nil || !over || cap(data) != 1<<20 {
		t.Fatalf("over: cap %d over %v err %v", cap(data), over, err)
	}
	// a lying Content-Length larger than the cap allocates only the cap
	data, over, _, _ = readCapped(strings.NewReader(body), 1<<40, 1<<20, big)
	if cap(data) > 1<<20 || over {
		t.Fatalf("huge hint: cap %d", cap(data))
	}
	// the budget is taken before any allocation and refuses past its max
	small := newReplyBudget(100<<10, 100<<10).taker("k")
	if _, _, held, err := readCapped(strings.NewReader(body), int64(len(body)), 1<<20, small); err != errOverBudget || held != 0 {
		t.Fatalf("budget: %v held %d", err, held)
	}
}

func TestGatewayReplyBudgetIs503AndCounted(t *testing.T) {
	f := newFixtureOpts(t, func(o *Options) { o.MaxReplyBytesInFlight = 1 << 10 })
	f.up1.set(openAIBackend(strings.Repeat("word ", 1000))) // a 5 KiB reply
	r := f.chat(agentKey, "chat-a")
	if typ, code := r.errCode(t); r.status != 503 || typ != "server_error" || code != "overloaded" || len(f.up2.calls()) != 0 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	h := f.do("GET", "/healthz", "", nil).json(t)
	if h["status"] != "ok" || h["replies_overloaded"] != 1.0 {
		t.Fatalf("healthz %v", h)
	}
	// once the reply is written its bytes are given back: a small reply fits again
	f.up1.set(openAIBackend("short"))
	if r := f.chat(agentKey, "chat-a"); r.status != 200 {
		t.Fatalf("after: %d %s", r.status, r.body)
	}
}

func TestGatewayReplyBudgetIsSharedPerKey(t *testing.T) {
	// 64 KiB in all, 16 KiB a key: agent-a's stuck replies can hold only its share
	f := newFixtureOpts(t, func(o *Options) {
		o.MaxReplyBytesInFlight, o.MaxReplyBytesInFlightPerKey = 64<<10, 16<<10
	})
	release := make(chan struct{})
	defer close(release)
	f.up1.set(func(w http.ResponseWriter, r *http.Request, _ map[string]any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprint(15<<10))
		w.WriteHeader(200)
		w.Write([]byte("{"))
		w.(http.Flusher).Flush()
		select { // stuck mid-reply
		case <-release:
		case <-r.Context().Done():
		}
	})
	results := make(chan int, 4)
	for i := 0; i < 4; i++ {
		go func() {
			req, _ := http.NewRequest("POST", f.gw.URL+"/v1/chat/completions", strings.NewReader(string(mustJSON(chatBody("chat-a")))))
			req.Header.Set("Authorization", "Bearer "+agentKey)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				results <- 0
				return
			}
			resp.Body.Close()
			results <- resp.StatusCode
		}()
	}
	// one stuck call holds 15 KiB of agent-a's 16: the other three are refused at once
	for i := 0; i < 3; i++ {
		select {
		case st := <-results:
			if st != 503 {
				t.Fatalf("agent-a over its share: %d", st)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("agent-a's calls over its share were not refused")
		}
	}
	// local-b's 5 KiB reply still fits the global budget: it is not starved
	f.up3.set(openAIBackend(strings.Repeat("word ", 1000)))
	if r := f.chat(localKey, "chat-b"); r.status != 200 {
		t.Fatalf("local-b starved: %d %s", r.status, r.body)
	}
}
