// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"io"
	"net/http"
	"strings"
)

// maxSSELine bounds one line of an upstream event stream.
const maxSSELine = 8 << 20

// sseEvent is one server-sent event: its data lines joined by "\n".
type sseEvent struct {
	event string
	data  string
}

type sseReader struct{ sc *bufio.Scanner }

func newSSEReader(r io.Reader) *sseReader { return newSSEReaderSize(r, maxSSELine) }

// newSSEReaderSize is newSSEReader with a line bound of maxLine bytes (its tests use a small one).
// The scanner's first buffer is never larger than the bound, because bufio.Scanner takes the
// larger of the two as its limit.
func newSSEReaderSize(r io.Reader, maxLine int) *sseReader {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, min(64*1024, maxLine)), maxLine)
	return &sseReader{sc: sc}
}

// next returns the next event with data; io.EOF at the end of the stream.
func (r *sseReader) next() (sseEvent, error) {
	var ev sseEvent
	var data []string
	for r.sc.Scan() {
		line := strings.TrimSuffix(r.sc.Text(), "\r")
		if line == "" {
			if len(data) > 0 {
				ev.data = strings.Join(data, "\n")
				return ev, nil
			}
			ev = sseEvent{}
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "data":
			data = append(data, value)
		case "event":
			ev.event = value
		}
	}
	if err := r.sc.Err(); err != nil {
		return sseEvent{}, err
	}
	if len(data) > 0 {
		ev.data = strings.Join(data, "\n")
		return ev, nil
	}
	return sseEvent{}, io.EOF
}

// sseWriter sends OpenAI-style chunks to the caller, flushing each.
type sseWriter struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func startSSE(w http.ResponseWriter) *sseWriter {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	return &sseWriter{w: w, rc: http.NewResponseController(w)}
}

func (s *sseWriter) send(data []byte) error {
	extendDeadline(s.w)
	if _, err := io.WriteString(s.w, "data: "); err != nil {
		return err
	}
	if _, err := s.w.Write(data); err != nil {
		return err
	}
	if _, err := io.WriteString(s.w, "\n\n"); err != nil {
		return err
	}
	return s.rc.Flush()
}

func (s *sseWriter) done() error { return s.send([]byte("[DONE]")) }

// estimateTokens is the ADR-0038 d4 estimate for a stream that reported no usage.
func estimateTokens(contentBytes int) int { return (contentBytes + 3) / 4 }
