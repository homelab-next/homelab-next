// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"sync"
	"time"
)

// Defaults for the write deadline and the in-flight caps (security audit M1).
const (
	DefaultWriteTimeout      = 60 * time.Second
	DefaultMaxInFlight       = 256
	DefaultMaxInFlightPerKey = 32
)

// deadlineWriter gives every write to the caller a deadline, so a caller that stops reading
// cannot hold a handler (and the reply it holds) forever. The deadline is set when a request
// arrives, when a reply starts (a non-streamed reply's whole body is written under that one
// deadline) and before every streamed event.
type deadlineWriter struct {
	http.ResponseWriter
	rc *http.ResponseController
	d  time.Duration
}

func newDeadlineWriter(w http.ResponseWriter, d time.Duration) *deadlineWriter {
	dw := &deadlineWriter{ResponseWriter: w, rc: http.NewResponseController(w), d: d}
	dw.extend()
	return dw
}

// extend sets the write deadline d from now (a writer that has none, such as a test recorder,
// is left as it is).
func (w *deadlineWriter) extend() { _ = w.rc.SetWriteDeadline(time.Now().Add(w.d)) }

func (w *deadlineWriter) WriteHeader(code int) {
	w.extend()
	w.ResponseWriter.WriteHeader(code)
}

func (w *deadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// extendDeadline extends w's write deadline when w is a deadlineWriter.
func extendDeadline(w http.ResponseWriter) {
	if dw, ok := w.(*deadlineWriter); ok {
		dw.extend()
	}
}

// inFlight caps the model calls running at once, in all and per caller key. A call over a cap
// is refused (429 concurrency_limited) before its body is read, so it consumes nothing.
type inFlight struct {
	mu        sync.Mutex
	max       int
	perKeyMax int
	total     int
	perKey    map[string]int

	refused int       // refusals since the last log line
	logged  time.Time // when the last log line was written
}

func newInFlight(max, perKeyMax int) *inFlight {
	return &inFlight{max: max, perKeyMax: perKeyMax, perKey: map[string]int{}}
}

// acquire takes a slot for key; release must be called once when ok.
func (f *inFlight) acquire(key string) (release func(), ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.total >= f.max || f.perKey[key] >= f.perKeyMax {
		f.refused++
		return nil, false
	}
	f.total++
	f.perKey[key]++
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.total--
		if f.perKey[key]--; f.perKey[key] == 0 {
			delete(f.perKey, key)
		}
	}, true
}

// refusals returns the refusals since the last call, at most once a second (0 otherwise), so a
// flood of them is logged as one line a second.
func (f *inFlight) refusals(now time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refused == 0 || now.Sub(f.logged) < time.Second {
		return 0
	}
	n := f.refused
	f.refused, f.logged = 0, now
	return n
}
