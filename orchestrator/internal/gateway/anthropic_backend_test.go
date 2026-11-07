// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"strings"
)

// anthropicBackend answers like the Messages API.
func anthropicBackend(reply string) func(http.ResponseWriter, *http.Request, map[string]any) {
	return func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		if body["stream"] == true {
			w.Header().Set("Content-Type", "text/event-stream")
			ev := func(name string, v map[string]any) {
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, mustJSON(v))
			}
			ev("message_start", map[string]any{"type": "message_start", "message": map[string]any{
				"id": "msg_1", "model": body["model"], "usage": map[string]any{"input_tokens": 9, "output_tokens": 1}}})
			ev("ping", map[string]any{"type": "ping"})
			ev("content_block_start", map[string]any{"type": "content_block_start", "index": 0})
			for _, p := range strings.Fields(reply) {
				ev("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0,
					"delta": map[string]any{"type": "text_delta", "text": p + " "}})
			}
			ev("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
			ev("message_delta", map[string]any{"type": "message_delta",
				"delta": map[string]any{"stop_reason": "end_turn"}, "usage": map[string]any{"output_tokens": 4}})
			ev("message_stop", map[string]any{"type": "message_stop"})
			return
		}
		writeTestJSON(w, 200, map[string]any{"id": "msg_1", "type": "message", "role": "assistant",
			"model": body["model"], "content": []any{map[string]any{"type": "text", "text": reply}},
			"stop_reason": "max_tokens", "usage": map[string]any{"input_tokens": 9, "output_tokens": 4,
				"cache_read_input_tokens": 3}})
	}
}
