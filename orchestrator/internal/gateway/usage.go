// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"container/heap"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// UsageRecord is one admission decision and its served outcome (ADR-0038 d6): names and
// numbers only, never prompt or reply text. Its field names are the neutral turn record's where
// the two overlap (conformance/protocols/inference.py TURN_FIELDS).
type UsageRecord struct {
	TS              string     `json:"ts"`
	TurnID          string     `json:"turn_id"`
	GatewayTag      *string    `json:"gateway_tag"`
	Key             string     `json:"key"`
	Owner           string     `json:"owner"`
	ModelRole       string     `json:"model_role"`
	ServedRole      *string    `json:"served_role"`
	Model           string     `json:"model"`
	Deployment      *string    `json:"deployment"`
	CallType        string     `json:"call_type"`
	Stream          bool       `json:"stream"`
	Status          int        `json:"status"`
	ErrorCode       *string    `json:"error_code"`
	InputTokens     *int       `json:"input_tokens"`
	OutputTokens    *int       `json:"output_tokens"`
	CacheReadTokens *int       `json:"cache_read_tokens"`
	CacheHit        *bool      `json:"cache_hit"`
	CostUSD         *float64   `json:"cost_usd"`
	TTFTMS          *int64     `json:"ttft_ms"`
	DurationMS      int64      `json:"duration_ms"`
	Fallbacks       int        `json:"fallbacks"`
	UsageEstimated  bool       `json:"usage_estimated"`
	TLP             *TLPRecord `json:"tlp"`
	// Count is how many decisions the record stands for: 1, or for an aggregated refusal the
	// identical refusals within its second (AppendRefusal: every field but ts, turn_id and
	// duration_ms is the same).
	Count int `json:"count"`
	// AggregatedOverflow marks the catch-all record of a key's refusals beyond the
	// MaxHeldRefusalsPerKey distinct kinds held at once: count is per key and error_code only,
	// gateway_tag is null, and its other fields are those of the first refusal folded into it.
	AggregatedOverflow bool `json:"aggregated_overflow"`
}

// TLPRecord is the admission verdict on the requested role; null when the request was refused
// before TLP was judged (scope).
type TLPRecord struct {
	Label     string `json:"label"`
	Ceiling   string `json:"ceiling"`
	LeavesLab bool   `json:"leaves_lab"`
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason"`
}

// MaxUsageRecords caps one /v1/usage reply.
const MaxUsageRecords = 10000

// DefaultUsageQueue is how many records may wait for the usage writer before new ones are
// dropped.
const DefaultUsageQueue = 4096

// maxUsageBatch is the most records the writer writes before one fsync.
const maxUsageBatch = 256

// refusalHold is how long identical refusals are counted into one record.
const refusalHold = time.Second

// MaxHeldRefusalsPerKey is how many distinct refusal records one key may have held at once
// (each held for refusalHold); more distinct refusals of that key fold into one overflow record
// per error_code, so varying a field (X-HNX-Tag, the role) cannot multiply its records.
const MaxHeldRefusalsPerKey = 16

// DefaultRefusalQueue is the size of the refusal records' own queue: they wait there, never in
// the served calls' queue, so a refusal flood cannot crowd out a served call's record.
const DefaultRefusalQueue = 1024

// UsageOptions configure a UsageLog.
type UsageOptions struct {
	// QueueSize is DefaultUsageQueue when zero; RefusalQueueSize is DefaultRefusalQueue.
	QueueSize, RefusalQueueSize int
	// Logger receives the writer's failures and drops (discarded when nil).
	Logger *slog.Logger

	sync func(*os.File) error // tests stall or fail the fsync
}

// UsageLog is an append-only JSON-lines file, mode 0600. Records are queued (Append never
// waits on the disk) and written by one writer, which fsyncs once per group of records. When
// the queue is full a record is dropped; when the file cannot be written the group is lost.
// Either way serving continues, and the drops are counted (Dropped) and logged as an error at
// most once a second. Refusals are aggregated (AppendRefusal).
type UsageLog struct {
	path     string
	f        *os.File
	log      *slog.Logger
	sync     func(*os.File) error
	queue    chan UsageRecord // served calls (lane 0)
	refusals chan UsageRecord // aggregated refusals (lane 1)
	done     chan struct{}

	mu       sync.Mutex
	cond     *sync.Cond
	closed   bool
	enqueued [2]uint64 // records accepted into each lane's queue
	handled  [2]uint64 // of those, written or lost to a write error

	dropped     atomic.Uint64
	skipped     atomic.Uint64 // lines /v1/usage reads skipped, counted on every read
	dropMu      sync.Mutex
	dropLogged  time.Time
	dropLastSum uint64

	aggMu    sync.Mutex
	agg      map[string]*heldRefusal
	aggPerKy map[string]int // distinct (not overflow) held records per key
	aggSeq   uint64
}

type heldRefusal struct {
	rec      UsageRecord
	since    time.Time
	seq      uint64 // arrival order: held records are written in it
	overflow bool
}

// OpenUsageLog opens (creating) path for appending, makes it 0600 and starts its writer.
func OpenUsageLog(path string) (*UsageLog, error) { return OpenUsageLogWith(path, UsageOptions{}) }

// OpenUsageLogWith is OpenUsageLog with options.
func OpenUsageLogWith(path string, o UsageOptions) (*UsageLog, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, err
	}
	if o.QueueSize <= 0 {
		o.QueueSize = DefaultUsageQueue
	}
	if o.RefusalQueueSize <= 0 {
		o.RefusalQueueSize = DefaultRefusalQueue
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.sync == nil {
		o.sync = (*os.File).Sync
	}
	u := &UsageLog{path: path, f: f, log: o.Logger, sync: o.sync, queue: make(chan UsageRecord, o.QueueSize),
		refusals: make(chan UsageRecord, o.RefusalQueueSize), done: make(chan struct{}),
		agg: map[string]*heldRefusal{}, aggPerKy: map[string]int{}}
	u.cond = sync.NewCond(&u.mu)
	go u.writer()
	return u, nil
}

// Append queues one record; it never waits on the disk. It returns an error only when the log is
// closed; a full queue drops the record (counted and logged).
func (u *UsageLog) Append(r UsageRecord) error { return u.enqueue(0, r) }

func (u *UsageLog) enqueue(lane int, r UsageRecord) error {
	if r.Count == 0 {
		r.Count = 1
	}
	q, why := u.queue, "the queue is full"
	if lane == 1 {
		q, why = u.refusals, "the refusal queue is full"
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return errors.New("usage log closed")
	}
	select {
	case q <- r:
		u.enqueued[lane]++
	default:
		u.drop(1, why)
	}
	return nil
}

// refusalKey is what refusals must share to be merged into one record: every field but ts,
// turn_id, duration_ms and count (the tag, roles, status, error code and the whole TLP verdict
// included), so a merged record says nothing that is not true of every refusal it counts.
func refusalKey(r UsageRecord) string {
	r.TS, r.TurnID, r.DurationMS, r.Count = "", "", 0, 0
	return string(mustJSON(r))
}

// AppendRefusal counts a refusal: the first refusal of its kind (refusalKey) is held for a
// second and written once with count set to the number of identical refusals in the meantime,
// so a flood of refused calls writes at most one record per kind per second.
//
// A key holds at most MaxHeldRefusalsPerKey distinct records at once; a further distinct refusal
// of that key is counted into one overflow record per (key, error_code) instead, with
// gateway_tag null and aggregated_overflow true.
func (u *UsageLog) AppendRefusal(r UsageRecord) {
	k := refusalKey(r)
	u.aggMu.Lock()
	defer u.aggMu.Unlock()
	if h := u.agg[k]; h != nil {
		h.rec.Count++
		return
	}
	overflow := u.aggPerKy[r.Key] >= MaxHeldRefusalsPerKey
	if overflow {
		code := ""
		if r.ErrorCode != nil {
			code = *r.ErrorCode
		}
		k = "overflow\x00" + r.Key + "\x00" + code
		if h := u.agg[k]; h != nil {
			h.rec.Count++
			return
		}
		r.GatewayTag, r.AggregatedOverflow = nil, true
	} else {
		u.aggPerKy[r.Key]++
	}
	r.Count = 1
	u.aggSeq++
	u.agg[k] = &heldRefusal{rec: r, since: time.Now(), seq: u.aggSeq, overflow: overflow}
}

// releaseRefusals queues the held refusal records older than refusalHold (all of them when all).
func (u *UsageLog) releaseRefusals(all bool) {
	u.aggMu.Lock()
	var out []*heldRefusal
	now := time.Now()
	for k, h := range u.agg {
		if all || now.Sub(h.since) >= refusalHold {
			out = append(out, h)
			delete(u.agg, k)
			if !h.overflow {
				if u.aggPerKy[h.rec.Key]--; u.aggPerKy[h.rec.Key] <= 0 {
					delete(u.aggPerKy, h.rec.Key)
				}
			}
		}
	}
	u.aggMu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	for _, h := range out {
		_ = u.enqueue(1, h.rec)
	}
}

// drop counts n lost records and logs it, at most once a second. Called with u.mu held or not.
func (u *UsageLog) drop(n uint64, why string) {
	total := u.dropped.Add(n)
	u.dropMu.Lock()
	defer u.dropMu.Unlock()
	if now := time.Now(); now.Sub(u.dropLogged) >= time.Second {
		u.log.Error("usage records dropped", "dropped", total-u.dropLastSum, "dropped_total", total, "why", why,
			"path", u.path)
		u.dropLogged, u.dropLastSum = now, total
	}
}

// Skipped is how many malformed or overlong lines Range has skipped since the log opened,
// counted once per read (a bad line read twice counts twice).
func (u *UsageLog) Skipped() uint64 { return u.skipped.Load() }

// Dropped is how many records were lost since the log opened (a full queue or a write error).
func (u *UsageLog) Dropped() uint64 { return u.dropped.Load() }

// writer writes queued records in groups, one fsync per group, from both lanes, until both
// queues are closed.
func (u *UsageLog) writer() {
	defer close(u.done)
	tick := time.NewTicker(refusalHold / 4)
	defer tick.Stop()
	batch := make([]UsageRecord, 0, maxUsageBatch)
	var buf []byte
	q, rq := u.queue, u.refusals
	for q != nil || rq != nil {
		var n [2]uint64
		batch = batch[:0]
		select {
		case r, ok := <-q:
			if !ok {
				q = nil
				continue
			}
			batch, n[0] = append(batch, r), 1
		case r, ok := <-rq:
			if !ok {
				rq = nil
				continue
			}
			batch, n[1] = append(batch, r), 1
		case <-tick.C:
			u.releaseRefusals(false)
			continue
		}
	more:
		for len(batch) < maxUsageBatch {
			select {
			case r, ok := <-q:
				if !ok {
					q = nil
					continue
				}
				batch = append(batch, r)
				n[0]++
			case r, ok := <-rq:
				if !ok {
					rq = nil
					continue
				}
				batch = append(batch, r)
				n[1]++
			default:
				break more
			}
		}
		buf = buf[:0]
		for _, r := range batch {
			line, err := json.Marshal(r)
			if err != nil {
				continue
			}
			buf = append(append(buf, line...), '\n')
		}
		_, err := u.f.Write(buf)
		if err == nil {
			err = u.sync(u.f)
		}
		if err != nil {
			u.log.Error("usage log write failed: serving continues without these records", "err", err, "records", len(batch))
			u.drop(uint64(len(batch)), "the file could not be written")
		}
		u.mu.Lock()
		u.handled[0] += n[0]
		u.handled[1] += n[1]
		u.cond.Broadcast()
		u.mu.Unlock()
	}
}

// Flush queues every held refusal and waits (up to timeout) until every record queued so far is
// written; false when it gave up waiting.
func (u *UsageLog) Flush(timeout time.Duration) bool {
	u.releaseRefusals(true)
	u.mu.Lock()
	defer u.mu.Unlock()
	target := u.enqueued
	deadline := time.Now().Add(timeout)
	stop := time.AfterFunc(timeout, func() {
		u.mu.Lock()
		u.cond.Broadcast()
		u.mu.Unlock()
	})
	defer stop.Stop()
	for u.handled[0] < target[0] || u.handled[1] < target[1] {
		if time.Now().After(deadline) {
			return false
		}
		u.cond.Wait()
	}
	return true
}

// Close writes what is queued and held, then closes the file.
func (u *UsageLog) Close() error {
	u.releaseRefusals(true)
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil
	}
	u.closed = true
	close(u.queue)
	close(u.refusals)
	u.mu.Unlock()
	<-u.done
	return u.f.Close()
}

// maxUsageLine is the longest usage line Range reads; a longer one is skipped.
const maxUsageLine = 1 << 20

// Range returns the records whose ts is within [start, end) (end exclusive) and, when tag is
// not empty, whose gateway_tag is tag: the earliest MaxUsageRecords of them by ts, in ts order
// (ties in file order), and whether more matched (callers page by time, and de-duplicate by
// turn_id where pages meet). A line that is malformed or longer than 1 MiB is skipped, counted
// and logged; it never fails the read.
func (u *UsageLog) Range(start, end time.Time, tag string) ([]UsageRecord, bool, error) {
	if !u.Flush(5 * time.Second) {
		u.log.Warn("usage read: the writer is behind; the reply may miss the newest records")
	}
	f, err := os.Open(u.path)
	if errors.Is(err, fs.ErrNotExist) {
		return []UsageRecord{}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	h := &usageHeap{}
	truncated, skipped := false, 0
	rd := bufio.NewReaderSize(f, maxUsageLine)
	for seq := 0; ; seq++ {
		line, err := rd.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			skipped++
			for errors.Is(err, bufio.ErrBufferFull) { // the rest of the overlong line
				_, err = rd.ReadSlice('\n')
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, false, err
			}
			if err != nil {
				break
			}
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, false, err
		}
		if t := bytes.TrimSpace(line); len(t) > 0 {
			var r UsageRecord
			ts, perr := time.Time{}, json.Unmarshal(t, &r)
			if perr == nil {
				ts, perr = time.Parse(time.RFC3339Nano, r.TS)
			}
			switch {
			case perr != nil:
				skipped++
			case ts.Before(start) || !ts.Before(end):
			case tag != "" && (r.GatewayTag == nil || *r.GatewayTag != tag):
			default:
				if r.Count == 0 {
					r.Count = 1
				}
				e := usageEntry{ts: ts, seq: seq, rec: r}
				switch {
				case h.Len() < MaxUsageRecords:
					heap.Push(h, e)
				case e.before((*h)[0]):
					(*h)[0] = e
					heap.Fix(h, 0)
					truncated = true
				default:
					truncated = true
				}
			}
		}
		if err != nil { // io.EOF
			break
		}
	}
	if skipped > 0 {
		u.skipped.Add(uint64(skipped))
		u.log.Warn("usage read: skipped malformed or overlong lines", "skipped", skipped, "path", u.path)
	}
	entries := []usageEntry(*h)
	sort.Slice(entries, func(i, j int) bool { return entries[i].before(entries[j]) })
	out := make([]UsageRecord, len(entries))
	for i, e := range entries {
		out[i] = e.rec
	}
	return out, truncated, nil
}

type usageEntry struct {
	ts  time.Time
	seq int
	rec UsageRecord
}

func (a usageEntry) before(b usageEntry) bool {
	if !a.ts.Equal(b.ts) {
		return a.ts.Before(b.ts)
	}
	return a.seq < b.seq
}

// usageHeap is a max-heap: its root is the latest of the earliest records kept.
type usageHeap []usageEntry

func (h usageHeap) Len() int           { return len(h) }
func (h usageHeap) Less(i, j int) bool { return h[j].before(h[i]) }
func (h usageHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *usageHeap) Push(x any)        { *h = append(*h, x.(usageEntry)) }
func (h *usageHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	*h = old[:len(old)-1]
	return e
}
