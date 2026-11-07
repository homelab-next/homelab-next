// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxReplyBytes bounds a non-streamed upstream reply the gateway reads. The reply is held once
// (its model is rewritten in place, see relayOpenAIReply); with the in-flight caps this bounds
// the memory replies can take.
const maxReplyBytes = 16 << 20

// NewUpstreamClient is the client for upstream calls. It follows no redirect (a redirect is an
// upstream failure: following one would carry the provider key to wherever Location points)
// and reads no proxy from the environment: proxy is used when, and only when, it is non-nil.
func NewUpstreamClient(proxy *url.URL) *http.Client {
	t := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if proxy != nil {
		t.Proxy = http.ProxyURL(proxy)
	}
	return &http.Client{
		Transport:     t,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// UpstreamUserAgent is the fixed User-Agent of every upstream request.
const UpstreamUserAgent = "hnx-gateway"

// result is what one attempt did. answered: the caller has its reply (a success, or an upstream
// 4xx returned as-is); otherwise nothing was written and reason says why the next may be tried.
type result struct {
	answered     bool
	status       int
	code         string // the contract error code of a refusal, else ""
	usage        tokenUsage
	ttft         *time.Duration
	reason       string
	credsRefused bool
	// unsupported: the deployment cannot take this request at all (nothing was sent); the next
	// deployment may, and if none can this is the caller's answer.
	unsupported *apiError
	upstreamOK  bool // the upstream answered 2xx (whatever the gateway then did with the reply)
}

func failed(format string, a ...any) result { return result{reason: fmt.Sprintf(format, a...)} }

// attemptTimer cancels an attempt once it has waited the timeout: for the whole reply, or (a
// stream) for each next event, since reset is called per event.
type attemptTimer struct {
	ctx    context.Context
	cancel context.CancelFunc
	timer  *time.Timer
	d      time.Duration
}

func newAttemptTimer(parent context.Context, d time.Duration) *attemptTimer {
	ctx, cancel := context.WithCancel(parent)
	return &attemptTimer{ctx: ctx, cancel: cancel, timer: time.AfterFunc(d, cancel), d: d}
}

func (a *attemptTimer) reset() { a.timer.Reset(a.d) }

func (a *attemptTimer) stop() {
	a.timer.Stop()
	a.cancel()
}

// attempt sends the call to one deployment.
func (s *Server) attempt(w http.ResponseWriter, r *http.Request, cl *call, d *Deployment) (res result) {
	var (
		path string
		body []byte
		err  *apiError
	)
	switch {
	case d.Protocol == "anthropic":
		path = "/v1/messages"
		body, err = toAnthropic(cl.body, d.Model)
	case d.Locality == "local" && cl.urlPart() != "":
		// a local backend would fetch the URL from inside the lab (security audit L5)
		err = badRequest("unsupported_parameter", "the request ("+cl.urlPart()+")"+
			" carries a URL, which this gateway does not send to a local deployment")
	case cl.kind == "embedding":
		path, body, err = "/v1/embeddings", withModel(cl.body, d.Model, false), nil
	default:
		path, body, err = "/v1/chat/completions", withModel(cl.body, d.Model, cl.stream), nil
	}
	if err != nil {
		// this deployment cannot take the request; another one may (design review 4)
		return result{unsupported: err, reason: err.message}
	}
	cl.called = true
	at := newAttemptTimer(r.Context(), s.timeout)
	defer at.stop()
	req, rerr := http.NewRequestWithContext(at.ctx, http.MethodPost, d.BaseURL+path, bytes.NewReader(body))
	if rerr != nil {
		return failed("request: %v", rerr)
	}
	s.setUpstreamHeaders(req, d, cl.stream)
	client := s.localClient
	if d.Locality == "cloud" {
		client = s.cloudClient
	}
	resp, derr := client.Do(req)
	if derr != nil {
		return failed("transport: %v", derr)
	}
	defer resp.Body.Close()
	switch st := resp.StatusCode; {
	case st == http.StatusTooManyRequests || st >= 500:
		return failed("upstream HTTP %d", st)
	case st == http.StatusUnauthorized || st == http.StatusForbidden:
		res := failed("upstream HTTP %d: the gateway's credentials were refused", st)
		res.credsRefused = true
		return res
	case st >= 400:
		e := upstreamRejected(st)
		e.write(w)
		return result{answered: true, status: st, code: e.code}
	case st < 200 || st >= 300:
		return failed("upstream HTTP %d (no redirect is followed)", st)
	}
	// the upstream accepted the call and may have generated its answer: if the gateway throws the
	// reply away (malformed, over the cap, over the reply budget, a stream that broke before its
	// first chunk), the attempt is still charged
	defer func() { res.upstreamOK = true }()
	isSSE := strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")
	switch {
	case cl.stream && isSSE && d.Protocol == "anthropic":
		return s.relayAnthropicStream(w, resp, cl, at)
	case cl.stream && isSSE:
		return s.relayOpenAIStream(w, resp, cl, at)
	case isSSE:
		return failed("an event stream answered a request that did not ask for one")
	case cl.stream:
		// nothing has reached the caller: another deployment may still stream the answer
		return failed("a stream was asked for and the upstream answered %q", resp.Header.Get("Content-Type"))
	}
	data, over, held, rerr := readCapped(resp.Body, resp.ContentLength, maxReplyBytes, s.replies.taker(cl.caller.alias()))
	defer s.replies.give(cl.caller.alias(), held) // after the reply is written
	switch {
	case errors.Is(rerr, errOverBudget):
		// the gateway is holding as many reply bytes as it may: the caller is told so, at once
		s.log.Warn("reply refused: the in-flight reply budget is spent", "request_id", cl.id, "deployment", d.ID)
		errOverloaded.write(w)
		return result{answered: true, status: errOverloaded.status, code: errOverloaded.code}
	case rerr != nil:
		return failed("reading the reply: %v", rerr)
	case over:
		return failed("reply over %d bytes", maxReplyBytes)
	}
	if d.Protocol == "anthropic" {
		return s.relayAnthropicReply(w, data, cl)
	}
	return relayOpenAIReply(w, data, cl)
}

func (s *Server) setUpstreamHeaders(req *http.Request, d *Deployment, stream bool) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UpstreamUserAgent)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	} else {
		req.Header.Set("Accept", "application/json")
	}
	key := s.secrets.upstreamKey(d)
	if d.Protocol == "anthropic" {
		req.Header.Set("anthropic-version", "2023-06-01")
		if key != "" {
			req.Header.Set("x-api-key", key)
		}
		return
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
}

// withModel re-encodes the request body with model replaced by the backend id (R5) and, for a
// stream, stream_options.include_usage set so the reply's tokens can be counted (R7).
func withModel(body map[string]json.RawMessage, model string, stream bool) []byte {
	out := make(map[string]json.RawMessage, len(body))
	for k, v := range body {
		out[k] = v
	}
	out["model"] = mustJSON(model)
	if stream {
		opts := map[string]json.RawMessage{}
		_ = json.Unmarshal(body["stream_options"], &opts)
		if opts == nil {
			opts = map[string]json.RawMessage{}
		}
		opts["include_usage"] = json.RawMessage("true")
		out["stream_options"] = mustJSON(opts)
	}
	return mustJSON(out)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // only ever called on values that marshal
	}
	return b
}

// relayOpenAIReply returns an OpenAI-compatible JSON reply with model set to the role alias. The
// reply is not decoded and re-encoded: its top-level model values are located and the reply is
// written around them, so it is held in memory once.
func relayOpenAIReply(w http.ResponseWriter, data []byte, cl *call) result {
	vals, open, ok := topLevel(data, "model", "usage", "choices")
	if !ok {
		return failed("the reply is not a JSON object")
	}
	u, ok := openAIUsage(last(data, vals["usage"]))
	if !ok {
		u = estimateUsage(cl, replyContentBytes(last(data, vals["choices"])))
	}
	cl.markServed(w)
	writeParts(w, http.StatusOK, replaceValues(data, vals["model"], open, "model", mustJSON(cl.alias))...)
	return result{answered: true, status: http.StatusOK, usage: u}
}

// replyContentBytes is the size of a chat reply's message contents (0 for anything else).
func replyContentBytes(raw json.RawMessage) int {
	var choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	_ = json.Unmarshal(raw, &choices)
	n := 0
	for _, c := range choices {
		n += len(c.Message.Content)
	}
	return n
}

// estimateUsage is the usage counted for a reply that reported none (R7, M3): input estimated
// from the request body's size, output from the reply's content (none for an embedding).
func estimateUsage(cl *call, contentBytes int) tokenUsage {
	in := estimateTokens(cl.bodyBytes)
	out := estimateTokens(contentBytes)
	return tokenUsage{input: &in, output: &out, estimated: true}
}

// openAIUsage reads an OpenAI usage object; ok is false when there is none.
func openAIUsage(raw json.RawMessage) (tokenUsage, bool) {
	var u struct {
		Prompt     *int `json:"prompt_tokens"`
		Completion *int `json:"completion_tokens"`
		Details    *struct {
			Cached *int `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	}
	if len(raw) == 0 || string(raw) == "null" || json.Unmarshal(raw, &u) != nil {
		return tokenUsage{}, false
	}
	t := tokenUsage{input: u.Prompt, output: u.Completion}
	if u.Details != nil && u.Details.Cached != nil && *u.Details.Cached >= 0 {
		t.cacheRead = u.Details.Cached
	}
	return t, true
}
