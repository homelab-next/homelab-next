// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"time"
)

// openAIStream is the state of one relayed OpenAI-compatible stream.
type openAIStream struct {
	cl           *call
	usage        tokenUsage
	haveUsage    bool
	contentBytes int
	errorChunk   bool // the last chunk carried error and no choices
}

// chunk rewrites one upstream chunk: model is the role alias. keep is false for the usage-only
// chunk the gateway asked for on the caller's behalf (R7); ok is false for a chunk that is not
// a JSON object, which the gateway cannot rewrite and so never forwards.
func (st *openAIStream) chunk(data string) (out []byte, keep, ok bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &obj); err != nil || obj == nil {
		return nil, false, false
	}
	obj["model"] = mustJSON(st.cl.alias)
	_, hasErr := obj["error"]
	_, hasChoices := obj["choices"]
	st.errorChunk = hasErr && !hasChoices
	var choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
	}
	_ = json.Unmarshal(obj["choices"], &choices)
	for _, c := range choices {
		st.contentBytes += len(c.Delta.Content)
	}
	if u, has := openAIUsage(obj["usage"]); has {
		st.usage, st.haveUsage = u, true
		if len(choices) == 0 && !st.cl.includeUsage {
			return nil, false, true
		}
	}
	return mustJSON(obj), true, true
}

// relayOpenAIStream passes an SSE stream through, rewriting model in every chunk and flushing
// each. Until the first chunk is sent nothing has reached the caller, so a failure there lets
// the next deployment be tried; after it, a failure ends the stream.
func (s *Server) relayOpenAIStream(w http.ResponseWriter, resp *http.Response, cl *call, at *attemptTimer) result {
	rd := newSSEReader(resp.Body)
	st := &openAIStream{cl: cl}
	var out *sseWriter
	var ttft *time.Duration
	for {
		ev, err := rd.next()
		if err != nil {
			if out == nil {
				return failed("the stream ended before its first chunk: %v", err)
			}
			break
		}
		at.reset()
		if ev.data == "[DONE]" {
			if out == nil {
				return failed("the stream ended before its first chunk")
			}
			_ = out.done()
			break
		}
		data, keep, ok := st.chunk(ev.data)
		if !ok {
			if out == nil {
				return failed("the stream's first chunk is not JSON")
			}
			break
		}
		if !keep {
			continue
		}
		if out == nil && st.errorChunk {
			// an upstream that fails mid-request may say so in its first chunk: nothing was sent
			return failed("the stream's first chunk is an error")
		}
		if out == nil {
			cl.markServed(w)
			out = startSSE(w)
			d := s.now().Sub(cl.start)
			ttft = &d
		}
		if out.send(data) != nil {
			break
		}
	}
	u := st.usage
	if !st.haveUsage {
		u = estimateUsage(cl, st.contentBytes)
	}
	return result{answered: true, status: http.StatusOK, usage: u, ttft: ttft}
}
