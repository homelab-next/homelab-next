// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"time"
)

// anthropicEvent is the part of a Messages stream event the translation reads.
type anthropicEvent struct {
	Type    string `json:"type"`
	Message struct {
		ID    string         `json:"id"`
		Usage anthropicUsage `json:"usage"`
	} `json:"message"`
	Delta struct {
		Type       string `json:"type"`
		Text       string `json:"text"`
		StopReason string `json:"stop_reason"`
	} `json:"delta"`
	Usage *struct {
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// relayAnthropicStream translates a Messages event stream into OpenAI chat.completion.chunk
// events. message_start is the first byte: before it, a failure lets the next deployment be
// tried; after it, an error event or a broken stream ends the reply.
func (s *Server) relayAnthropicStream(w http.ResponseWriter, resp *http.Response, cl *call, at *attemptTimer) result {
	rd := newSSEReader(resp.Body)
	var (
		out          *sseWriter
		ttft         *time.Duration
		id           string
		created      int64
		usage        anthropicUsage
		haveUsage    bool
		contentBytes int
	)
	chunk := func(delta map[string]any, finish any) []byte {
		return mustJSON(map[string]any{"id": id, "object": "chat.completion.chunk", "created": created,
			"model": cl.alias, "choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}}})
	}
	finish := func() result {
		u := usage.tokens()
		if !haveUsage {
			u = estimateUsage(cl, contentBytes)
		}
		return result{answered: true, status: http.StatusOK, usage: u, ttft: ttft}
	}
	for {
		raw, err := rd.next()
		if err != nil {
			if out == nil {
				return failed("the stream ended before message_start: %v", err)
			}
			return finish()
		}
		at.reset()
		var ev anthropicEvent
		if json.Unmarshal([]byte(raw.data), &ev) != nil {
			if out == nil {
				return failed("an event before message_start is not JSON")
			}
			return finish()
		}
		if out == nil {
			switch ev.Type {
			case "message_start":
			case "error":
				return failed("the stream began with an error event")
			default:
				continue
			}
		}
		var send []byte
		switch ev.Type {
		case "message_start":
			id, created = ev.Message.ID, s.now().Unix()
			usage, haveUsage = ev.Message.Usage, true
			cl.markServed(w)
			out = startSSE(w)
			d := s.now().Sub(cl.start)
			ttft = &d
			send = chunk(map[string]any{"role": "assistant", "content": ""}, nil)
		case "content_block_delta":
			if ev.Delta.Type != "text_delta" {
				continue
			}
			contentBytes += len(ev.Delta.Text)
			send = chunk(map[string]any{"content": ev.Delta.Text}, nil)
		case "message_delta":
			if ev.Usage != nil {
				usage.OutputTokens = ev.Usage.OutputTokens
			}
			if ev.Delta.StopReason == "" {
				continue
			}
			send = chunk(map[string]any{}, finishReason(ev.Delta.StopReason))
		case "message_stop":
			if cl.includeUsage {
				_ = out.send(mustJSON(map[string]any{"id": id, "object": "chat.completion.chunk",
					"created": created, "model": cl.alias, "choices": []any{}, "usage": openAIUsageObject(usage.tokens())}))
			}
			_ = out.done()
			return finish()
		case "error":
			return finish()
		default:
			continue
		}
		if out.send(send) != nil {
			return finish()
		}
	}
}
