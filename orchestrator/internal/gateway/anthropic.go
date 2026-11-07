// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
)

// defaultMaxTokens is the Messages API's required max_tokens when the request gives none.
const defaultMaxTokens = 1024

type anthropicRequest struct {
	Model         string             `json:"model"`
	System        string             `json:"system,omitempty"`
	Messages      []anthropicMessage `json:"messages"`
	MaxTokens     int                `json:"max_tokens"`
	Temperature   *float64           `json:"temperature,omitempty"`
	TopP          *float64           `json:"top_p,omitempty"`
	StopSequences []string           `json:"stop_sequences,omitempty"`
	Stream        bool               `json:"stream,omitempty"`
}

type anthropicMessage struct {
	Role    string           `json:"role"`
	Content []anthropicBlock `json:"content"`
}

type anthropicBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicUsage struct {
	InputTokens         int  `json:"input_tokens"`
	OutputTokens        int  `json:"output_tokens"`
	CacheCreationTokens int  `json:"cache_creation_input_tokens"`
	CacheReadTokens     *int `json:"cache_read_input_tokens"`
}

// unsupported are OpenAI request fields this translation cannot honour; a request that uses one
// is refused rather than silently answered without it.
var unsupported = []string{"tools", "tool_choice", "functions", "function_call", "response_format", "logprobs", "top_logprobs"}

// toAnthropic translates an OpenAI chat request into a Messages request: system and developer
// messages become system, consecutive turns of one role merge, max_tokens is the request's (or
// max_completion_tokens, or 1024). Only text content is translated.
func toAnthropic(body map[string]json.RawMessage, model string) ([]byte, *apiError) {
	for _, f := range unsupported {
		if raw, ok := body[f]; ok && string(raw) != "null" && string(raw) != "false" {
			return nil, badRequest("unsupported_parameter", f+" is not supported by this role's anthropic deployment")
		}
	}
	var n int
	if raw, ok := body["n"]; ok && (json.Unmarshal(raw, &n) != nil || n > 1) && string(raw) != "null" {
		return nil, badRequest("unsupported_parameter", "n > 1 is not supported by this role's anthropic deployment")
	}
	req := anthropicRequest{Model: model, MaxTokens: defaultMaxTokens}
	for _, f := range []string{"max_tokens", "max_completion_tokens"} {
		var v int
		if raw, ok := body[f]; ok && json.Unmarshal(raw, &v) == nil && v > 0 {
			req.MaxTokens = v
			break
		}
	}
	_ = json.Unmarshal(body["temperature"], &req.Temperature)
	_ = json.Unmarshal(body["top_p"], &req.TopP)
	_ = json.Unmarshal(body["stream"], &req.Stream)
	if raw, ok := body["stop"]; ok {
		var one string
		if json.Unmarshal(raw, &one) == nil {
			req.StopSequences = []string{one}
		} else if json.Unmarshal(raw, &req.StopSequences) != nil {
			return nil, badRequest("invalid_request", "stop must be a string or a list of strings")
		}
	}
	var msgs []map[string]json.RawMessage
	if json.Unmarshal(body["messages"], &msgs) != nil || len(msgs) == 0 {
		return nil, badRequest("invalid_request", "messages must be a non-empty list")
	}
	var system []string
	for _, m := range msgs {
		var role string
		_ = json.Unmarshal(m["role"], &role)
		if _, ok := m["tool_calls"]; ok {
			return nil, badRequest("unsupported_parameter", "tool calls are not supported by this role's anthropic deployment")
		}
		text, err := messageText(m["content"])
		if err != nil {
			return nil, err
		}
		switch role {
		case "system", "developer":
			system = append(system, text)
		case "user", "assistant":
			block := anthropicBlock{Type: "text", Text: text}
			if k := len(req.Messages); k > 0 && req.Messages[k-1].Role == role {
				req.Messages[k-1].Content = append(req.Messages[k-1].Content, block)
			} else {
				req.Messages = append(req.Messages, anthropicMessage{Role: role, Content: []anthropicBlock{block}})
			}
		default:
			return nil, badRequest("unsupported_parameter", "message role "+role+" is not supported by this role's anthropic deployment")
		}
	}
	if len(req.Messages) == 0 {
		return nil, badRequest("invalid_request", "messages hold no user or assistant turn")
	}
	req.System = strings.Join(system, "\n\n")
	return mustJSON(req), nil
}

// messageText is a message's content: a string, or a list of text parts.
func messageText(raw json.RawMessage) (string, *apiError) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s, nil
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return "", badRequest("invalid_request", "message content must be a string or a list of parts")
	}
	var b strings.Builder
	for _, p := range parts {
		if p.Type != "text" {
			return "", badRequest("unsupported_parameter", "content part "+p.Type+" is not supported by this role's anthropic deployment")
		}
		b.WriteString(p.Text)
	}
	return b.String(), nil
}

// finishReason maps a Messages stop_reason to an OpenAI finish_reason.
func finishReason(stop string) string {
	switch stop {
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	case "refusal":
		return "content_filter"
	}
	return "stop"
}

func (u anthropicUsage) tokens() tokenUsage {
	in := u.InputTokens + u.CacheCreationTokens
	var cache *int
	if u.CacheReadTokens != nil && *u.CacheReadTokens >= 0 {
		in += *u.CacheReadTokens
		cache = u.CacheReadTokens
	}
	out := u.OutputTokens
	return tokenUsage{input: &in, output: &out, cacheRead: cache}
}

func openAIUsageObject(u tokenUsage) map[string]any {
	in, out := 0, 0
	if u.input != nil {
		in = *u.input
	}
	if u.output != nil {
		out = *u.output
	}
	return map[string]any{"prompt_tokens": in, "completion_tokens": out, "total_tokens": in + out}
}

// relayAnthropicReply translates a Messages reply into an OpenAI chat.completion.
func (s *Server) relayAnthropicReply(w http.ResponseWriter, data []byte, cl *call) result {
	var m struct {
		ID         string           `json:"id"`
		Type       string           `json:"type"`
		Content    []anthropicBlock `json:"content"`
		StopReason string           `json:"stop_reason"`
		Usage      anthropicUsage   `json:"usage"`
	}
	if json.Unmarshal(data, &m) != nil || m.Type != "message" {
		return failed("the reply is not a Messages reply")
	}
	var text strings.Builder
	for _, b := range m.Content {
		if b.Type == "text" {
			text.WriteString(b.Text)
		}
	}
	u := m.Usage.tokens()
	cl.markServed(w)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": m.ID, "object": "chat.completion", "created": s.now().Unix(), "model": cl.alias,
		"choices": []any{map[string]any{"index": 0, "finish_reason": finishReason(m.StopReason),
			"message": map[string]any{"role": "assistant", "content": text.String()}}},
		"usage": openAIUsageObject(u),
	})
	return result{answered: true, status: http.StatusOK, usage: u}
}
