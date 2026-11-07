// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
)

// DefaultMaxReplyBytesInFlight bounds the memory every non-streamed reply being read holds at
// once.
const DefaultMaxReplyBytesInFlight = 512 << 20

// errOverBudget is a reply that the in-flight reply-bytes budget cannot hold.
var errOverBudget = errors.New("the in-flight reply budget is spent")

// replyBudget is the gateway-wide budget of bytes held by non-streamed replies being read, and
// each caller key's share of it: one key's stuck callers can hold at most perKeyMax, so they
// cannot starve the other keys.
type replyBudget struct {
	mu        sync.Mutex
	max       int64
	perKeyMax int64
	used      int64
	perKey    map[string]int64
	refused   atomic.Uint64
}

func newReplyBudget(max, perKeyMax int64) *replyBudget {
	if perKeyMax <= 0 || perKeyMax > max {
		perKeyMax = max / 4
	}
	return &replyBudget{max: max, perKeyMax: perKeyMax, perKey: map[string]int64{}}
}

func (b *replyBudget) take(key string, n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used+n > b.max || b.perKey[key]+n > b.perKeyMax {
		b.refused.Add(1)
		return false
	}
	b.used += n
	b.perKey[key] += n
	return true
}

func (b *replyBudget) give(key string, n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used -= n
	if b.perKey[key] -= n; b.perKey[key] <= 0 {
		delete(b.perKey, key)
	}
}

// taker is take bound to key.
func (b *replyBudget) taker(key string) func(int64) bool {
	return func(n int64) bool { return b.take(key, n) }
}

// readCapped reads r into a buffer sized from hint (the reply's Content-Length, or 8 KiB when
// unknown), growing it at most to limit and taking every byte of capacity from the budget first
// (take); it
// never allocates past limit. over is true when r holds more than limit bytes. held is the
// capacity taken, which the caller gives back once the reply is written (also on an
// error).
func readCapped(r io.Reader, hint int64, limit int, take func(int64) bool) (data []byte, over bool, held int64, err error) {
	n := 8 << 10
	if hint > 0 {
		n = int(min(hint, int64(limit)))
	}
	n = min(n, limit)
	grow := func(c int) bool {
		if !take(int64(c - cap(data))) {
			return false
		}
		held += int64(c - cap(data))
		next := make([]byte, len(data), c)
		copy(next, data)
		data = next
		return true
	}
	if !grow(n) {
		return nil, false, held, errOverBudget
	}
	for {
		if len(data) == cap(data) {
			// full: probe for one more byte before growing, so that a reply exactly the size of
			// its Content-Length (or of the cap) is never given a bigger buffer
			var one [1]byte
			k, err := io.ReadFull(r, one[:])
			switch {
			case k == 0 && errors.Is(err, io.EOF):
				return data, false, held, nil
			case k == 0:
				return nil, false, held, err
			case len(data) >= limit:
				return data, true, held, nil
			}
			if !grow(min(2*cap(data), limit)) {
				return nil, false, held, errOverBudget
			}
			data = append(data, one[0])
			continue
		}
		k, err := r.Read(data[len(data):cap(data)])
		data = data[:len(data)+k]
		if errors.Is(err, io.EOF) {
			return data, false, held, nil
		}
		if err != nil {
			return nil, false, held, err
		}
	}
}
