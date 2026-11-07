// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

var recordFields = []string{"aggregated_overflow", "cache_hit", "cache_read_tokens", "call_type", "cost_usd", "count", "deployment",
	"duration_ms", "error_code", "fallbacks", "gateway_tag", "input_tokens", "key", "model", "model_role",
	"output_tokens", "owner", "served_role", "status", "stream", "tlp", "ts", "ttft_ms", "turn_id", "usage_estimated"}

func TestGatewayUsageRecordsAreContentFree(t *testing.T) {
	f := newFixture(t)
	prompt := "PROMPT-SENTINEL-71c3"
	f.up3.set(openAIBackend("REPLY-SENTINEL-9e2a"))
	body := map[string]any{"model": "chat-b", "messages": []any{map[string]any{"role": "user", "content": prompt}}}
	f.do("POST", "/v1/chat/completions", agentKey, body, "X-HNX-Tag", "job-7")
	f.chat(localKey, "chat-a") // scope refusal: recorded
	f.chat(agentKey, "cloud")  // tlp refusal: recorded
	f.chat(agentKey, "nope")   // 400 before the decision: not recorded
	f.records()                // flushes the writer
	raw, err := os.ReadFile(f.usage)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "SENTINEL") || strings.Contains(string(raw), agentKey) || strings.Contains(string(raw), "backend-b1") {
		t.Fatalf("content in the usage log: %s", raw)
	}
	if st, _ := os.Stat(f.usage); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d records", len(lines))
	}
	var recs []map[string]any
	for _, l := range lines {
		var m map[string]any
		_ = json.Unmarshal([]byte(l), &m)
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if fmt.Sprint(keys) != fmt.Sprint(recordFields) {
			t.Fatalf("fields %v", keys)
		}
		recs = append(recs, m)
	}
	ok := recs[0]
	if ok["key"] != "agent-a" || ok["owner"] != "profile:agent-a" || ok["model"] != "chat-b" || ok["gateway_tag"] != "job-7" ||
		ok["status"] != 200.0 || ok["error_code"] != nil || ok["call_type"] != "chat" || ok["cache_read_tokens"] != nil ||
		ok["cache_hit"] != nil || ok["ttft_ms"] != nil || ok["cost_usd"] != nil {
		t.Fatalf("served record %v", ok)
	}
	if !strings.HasSuffix(ok["ts"].(string), "Z") {
		t.Fatalf("ts %v", ok["ts"])
	}
	tlp := ok["tlp"].(map[string]any)
	if tlp["label"] != "red" || tlp["allowed"] != true || tlp["reason"] != "within-ceiling" || tlp["ceiling"] != "red" {
		t.Fatalf("tlp %v", tlp)
	}
	if recs[1]["status"] != 403.0 || recs[1]["error_code"] != "model_not_allowed" || recs[1]["tlp"] != nil || recs[1]["deployment"] != nil {
		t.Fatalf("scope record %v", recs[1])
	}
	if recs[2]["error_code"] != "tlp_refused" || recs[2]["tlp"].(map[string]any)["reason"] != "unlabelled" {
		t.Fatalf("tlp record %v", recs[2])
	}
}

func TestGatewayUsageRangeAndScope(t *testing.T) {
	f := newFixture(t)
	t0 := f.clock.Now().Unix()
	f.chat(agentKey, "chat-b", "X-HNX-Tag", "a")
	f.clock.Advance(100 * time.Second)
	f.chat(agentKey, "chat-b", "X-HNX-Tag", "b")
	get := func(key, q string) reply { return f.do("GET", "/v1/usage?"+q, key, nil) }
	count := func(r reply) int {
		var out struct {
			Records []any `json:"records"`
		}
		_ = json.Unmarshal(r.body, &out)
		return len(out.Records)
	}
	for _, c := range []struct {
		q    string
		want int
	}{
		{fmt.Sprintf("start=%d&end=%d", t0, t0), 1},
		{fmt.Sprintf("start=%d&end=%d", t0, t0+100), 2},
		{fmt.Sprintf("start=%d&end=%d", t0+1, t0+99), 0},
		{fmt.Sprintf("start=%d&end=%d&tag=b", t0, t0+100), 1},
		{fmt.Sprintf("start=%d&end=%d&tag=zz", t0, t0+100), 0},
	} {
		for _, key := range []string{telemetryKey, adminKey} {
			if r := get(key, c.q); r.status != 200 || count(r) != c.want {
				t.Errorf("%s: %d %d %s", c.q, r.status, count(r), r.body)
			}
		}
	}
	if r := get(agentKey, "start=0&end=1"); r.status != 403 {
		t.Fatalf("agent key: %d", r.status)
	}
	for _, q := range []string{"", "start=1", "start=x&end=2", "start=5&end=1", "start=0&end=1&tag=has%20space"} {
		if r := get(telemetryKey, q); r.status != 400 {
			t.Errorf("%q: %d", q, r.status)
		}
	}
}

func TestGatewayUsageCap(t *testing.T) {
	path := t.TempDir() + "/u.jsonl"
	u, err := OpenUsageLogWith(path, UsageOptions{QueueSize: MaxUsageRecords + 5})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	ts := time.Unix(1000, 0).UTC().Format(time.RFC3339Nano)
	for i := 0; i < MaxUsageRecords+5; i++ {
		if err := u.Append(UsageRecord{TS: ts, TurnID: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	// the cap is under test, not Range's own 5 s wait for the queue: flush first, so a slow
	// runner (-race, shuffled, every package at once) cannot read a partly written file
	if !u.Flush(time.Minute) {
		t.Fatal("the queued records were not written within a minute")
	}
	recs, truncated, err := u.Range(time.Unix(0, 0), time.Unix(2000, 0), "")
	if err != nil || len(recs) != MaxUsageRecords || !truncated {
		t.Fatalf("%d %v %v", len(recs), truncated, err)
	}
}

// stalledSync is an fsync that waits for release, and counts its calls.
type stalledSync struct {
	mu      sync.Mutex
	calls   int
	release chan struct{}
	err     error
}

func (s *stalledSync) sync(f *os.File) error {
	<-s.release
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return s.err
}

func (s *stalledSync) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.calls }

func TestGatewayReplyDoesNotWaitOnTheUsageLog(t *testing.T) {
	ss := &stalledSync{release: make(chan struct{})}
	f := newFixtureOpts(t, func(o *Options) {
		u, err := OpenUsageLogWith(t.TempDir()+"/u.jsonl", UsageOptions{sync: ss.sync})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { u.Close() })
		o.Usage = u
	})
	defer close(ss.release)
	done := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest("POST", f.gw.URL+"/v1/chat/completions", strings.NewReader(string(mustJSON(chatBody("chat-b")))))
		req.Header.Set("Authorization", "Bearer "+agentKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- 0
			return
		}
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	select {
	case st := <-done:
		if st != 200 {
			t.Fatalf("status %d", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reply waited on a stalled fsync")
	}
}

func TestGatewayUsageWriterGroupsFsyncs(t *testing.T) {
	ss := &stalledSync{release: make(chan struct{})}
	u, err := OpenUsageLogWith(t.TempDir()+"/u.jsonl", UsageOptions{sync: ss.sync})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	for i := 0; i < 600; i++ {
		_ = u.Append(UsageRecord{TS: "x", TurnID: fmt.Sprint(i)})
	}
	close(ss.release)
	if !u.Flush(5 * time.Second) {
		t.Fatal("flush timed out")
	}
	// the first record may be written alone; the rest wait behind its fsync and go in groups
	if n := ss.count(); n > 1+(600+maxUsageBatch-1)/maxUsageBatch {
		t.Fatalf("%d fsyncs for 600 records", n)
	}
	if u.Dropped() != 0 {
		t.Fatalf("dropped %d", u.Dropped())
	}
}

func TestGatewayUsageQueueFullDropsLoudly(t *testing.T) {
	var logs strings.Builder
	var lmu sync.Mutex
	logger := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		lmu.Lock()
		defer lmu.Unlock()
		return logs.Write(p)
	}), nil))
	ss := &stalledSync{release: make(chan struct{})}
	u, err := OpenUsageLogWith(t.TempDir()+"/u.jsonl", UsageOptions{QueueSize: 2, Logger: logger, sync: ss.sync})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	for i := 0; i < 10; i++ {
		if err := u.Append(UsageRecord{TS: "x"}); err != nil {
			t.Fatal(err) // a full queue is not the caller's error
		}
	}
	// at most 3 in the writer's hands (the first and the 2 it drained) and 2 queued: 5 dropped
	if u.Dropped() < 5 {
		t.Fatalf("dropped %d", u.Dropped())
	}
	close(ss.release)
	u.Flush(5 * time.Second)
	lmu.Lock()
	defer lmu.Unlock()
	if !strings.Contains(logs.String(), "usage records dropped") || !strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("logs %s", logs.String())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestGatewayUsageWriteFailureKeepsServing(t *testing.T) {
	ss := &stalledSync{release: make(chan struct{}), err: errors.New("disk full")}
	close(ss.release)
	var u *UsageLog
	f := newFixtureOpts(t, func(o *Options) {
		var err error
		u, err = OpenUsageLogWith(t.TempDir()+"/u.jsonl", UsageOptions{sync: ss.sync})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { u.Close() })
		o.Usage = u
	})
	for i := 0; i < 3; i++ {
		if r := f.chat(agentKey, "chat-b"); r.status != 200 {
			t.Fatalf("call %d: %d", i, r.status)
		}
	}
	f.waitIdle()
	u.Flush(5 * time.Second)
	if u.Dropped() != 3 {
		t.Fatalf("dropped %d, want 3", u.Dropped())
	}
}

func TestGatewayRefusalRecordsAreAggregated(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 50; i++ {
		f.chat(agentKey, "cloud") // tlp refused (unlabelled)
	}
	for i := 0; i < 5; i++ {
		f.chat(localKey, "chat-a") // scope refused
	}
	f.chat(localKey, "cloud")  // scope refused: same key and code, another role: its own record
	f.chat(agentKey, "chat-b") // served: never aggregated
	f.chat(agentKey, "chat-b")
	recs := f.records()
	byCode := map[string][]map[string]any{}
	for _, r := range recs {
		code, _ := r["error_code"].(string)
		byCode[code] = append(byCode[code], r)
	}
	if len(byCode["tlp_refused"]) != 1 || byCode["tlp_refused"][0]["count"] != 50.0 {
		t.Fatalf("tlp refusals %v", byCode["tlp_refused"])
	}
	if m := byCode["model_not_allowed"]; len(m) != 2 || m[0]["count"] != 5.0 || m[0]["model_role"] != "chat-a" ||
		m[1]["count"] != 1.0 || m[1]["model_role"] != "cloud" {
		t.Fatalf("scope refusals %v", byCode["model_not_allowed"])
	}
	if len(byCode[""]) != 2 || byCode[""][0]["count"] != 1.0 {
		t.Fatalf("served %v", byCode[""])
	}
}

func TestGatewayHeldRefusalsKeepArrivalOrder(t *testing.T) {
	u, err := OpenUsageLog(t.TempDir() + "/u.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	for i := 0; i < 20; i++ {
		code := fmt.Sprint("code-", i)
		u.AppendRefusal(UsageRecord{TS: "2026-11-07T12:00:00Z", Key: "k", ErrorCode: &code})
	}
	u.Flush(5 * time.Second)
	raw, _ := os.ReadFile(u.path)
	for i, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var r UsageRecord
		_ = json.Unmarshal([]byte(line), &r)
		if want := fmt.Sprint("code-", i); r.ErrorCode == nil || *r.ErrorCode != want {
			t.Fatalf("record %d is %v, want %s", i, r.ErrorCode, want)
		}
	}
}

func TestGatewayUsageRangeIsTheEarliestByTS(t *testing.T) {
	path := t.TempDir() + "/u.jsonl"
	var lines []string
	// written latest first: the file order is not the ts order
	for i := MaxUsageRecords + 4; i >= 0; i-- {
		ts := time.Unix(1000, int64(i)*1000).UTC().Format(time.RFC3339Nano)
		lines = append(lines, string(mustJSON(UsageRecord{TS: ts, TurnID: fmt.Sprint(i)})))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	u, err := OpenUsageLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	recs, truncated, err := u.Range(time.Unix(0, 0), time.Unix(2000, 0), "")
	if err != nil || !truncated || len(recs) != MaxUsageRecords {
		t.Fatalf("%d %v %v", len(recs), truncated, err)
	}
	for i, r := range recs {
		if r.TurnID != fmt.Sprint(i) || r.Count != 1 {
			t.Fatalf("record %d is %s", i, r.TurnID)
		}
	}
}

func TestGatewayUsageRangeSkipsBadLines(t *testing.T) {
	path := t.TempDir() + "/u.jsonl"
	ts := time.Unix(1000, 0).UTC().Format(time.RFC3339Nano)
	good := func(id string) string { return string(mustJSON(UsageRecord{TS: ts, TurnID: id})) }
	data := good("a") + "\n{not json\n" + `{"ts":"` + strings.Repeat("x", 2<<20) + `"}` + "\n" + good("b") + "\n" + good("c")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	u, err := OpenUsageLogWith(path, UsageOptions{Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	recs, _, err := u.Range(time.Unix(0, 0), time.Unix(2000, 0), "")
	if err != nil || len(recs) != 3 || recs[0].TurnID != "a" || recs[1].TurnID != "b" || recs[2].TurnID != "c" {
		t.Fatalf("%v %v", recs, err)
	}
	if !strings.Contains(logs.String(), "skipped=2") {
		t.Fatalf("logs %s", logs.String())
	}
}

func TestGatewayCostIsNullOnAnUpstreamRejection(t *testing.T) {
	f := newFixture(t, func(cfg map[string]any) { roleOf(cfg, "chat-b")["cost_per_1k_tokens"] = 1.0 })
	f.up3.set(status(400))
	if r := f.chat(agentKey, "chat-b"); r.status != 400 {
		t.Fatalf("%d", r.status)
	}
	f.up3.set(openAIBackend("ok"))
	f.chat(agentKey, "chat-b")
	recs := f.records()
	if recs[0]["status"] != 400.0 || recs[0]["cost_usd"] != nil || recs[1]["cost_usd"] == nil {
		t.Fatalf("records %v", recs)
	}
}

func TestGatewayRefusalAggregationKeyIsTheWholeRecord(t *testing.T) {
	f := newFixture(t)
	f.chat(agentKey, "cloud", "X-HNX-Tag", "tag-a") // tlp refused, unlabelled
	f.chat(agentKey, "cloud", "X-HNX-Tag", "tag-b")
	f.chat(agentKey, "cloud", "X-HNX-Tag", "tag-b")
	f.chat(agentKey, "cloud", "X-HNX-TLP", "amber") // above-ceiling, amber
	f.chat(agentKey, "cloud", "X-HNX-TLP", "red")   // above-ceiling, red
	recs := f.records()
	if len(recs) != 4 {
		t.Fatalf("%d records: %v", len(recs), recs)
	}
	count := map[string]float64{}
	for _, r := range recs {
		tag, _ := r["gateway_tag"].(string)
		tlp := r["tlp"].(map[string]any)
		count[fmt.Sprint(tag, "/", tlp["label"], "/", tlp["reason"])] = r["count"].(float64)
	}
	want := map[string]float64{"tag-a/red/unlabelled": 1, "tag-b/red/unlabelled": 2, "/amber/above-ceiling": 1, "/red/above-ceiling": 1}
	if fmt.Sprint(count) != fmt.Sprint(want) {
		t.Fatalf("groups %v", count)
	}
	r := f.do("GET", fmt.Sprintf("/v1/usage?start=0&end=%d&tag=tag-b", f.clock.Now().Unix()+10), adminKey, nil)
	var out struct {
		Records []map[string]any `json:"records"`
	}
	_ = json.Unmarshal(r.body, &out)
	if len(out.Records) != 1 || out.Records[0]["gateway_tag"] != "tag-b" || out.Records[0]["count"] != 2.0 {
		t.Fatalf("tag-b: %s", r.body)
	}
}

func TestGatewayHealthzCountsUsageLosses(t *testing.T) {
	ss := &stalledSync{release: make(chan struct{}), err: errors.New("disk full")}
	close(ss.release)
	var u *UsageLog
	f := newFixtureOpts(t, func(o *Options) {
		path := t.TempDir() + "/u.jsonl"
		if err := os.WriteFile(path, []byte("{not json\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var err error
		if u, err = OpenUsageLogWith(path, UsageOptions{sync: ss.sync}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { u.Close() })
		o.Usage = u
	})
	f.chat(agentKey, "chat-b")
	f.chat(agentKey, "chat-b")
	f.records() // flushes (both records are lost to the failing fsync) and skips the bad line
	h := f.do("GET", "/healthz", "", nil).json(t)
	if h["status"] != "ok" || h["usage_records_dropped"] != 2.0 || h["usage_lines_skipped"] != 1.0 {
		t.Fatalf("healthz %v", h)
	}
}

func TestGatewayRefusalOverflowFoldsVariedRefusals(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 50; i++ { // 50 distinct tags: 50 distinct refusal kinds from one key
		f.chat(agentKey, "cloud", "X-HNX-Tag", fmt.Sprint("t-", i))
	}
	f.chat(localKey, "chat-a", "X-HNX-Tag", "other-key") // another key is not folded
	recs := f.records()
	var tagged, overflow []map[string]any
	for _, r := range recs {
		switch {
		case r["key"] != "agent-a":
		case r["aggregated_overflow"] == true:
			overflow = append(overflow, r)
		default:
			tagged = append(tagged, r)
		}
	}
	if len(tagged) != MaxHeldRefusalsPerKey || len(overflow) != 1 || len(recs) != MaxHeldRefusalsPerKey+2 {
		t.Fatalf("%d tagged, %d overflow, %d in all", len(tagged), len(overflow), len(recs))
	}
	o := overflow[0]
	if o["gateway_tag"] != nil || o["count"] != float64(50-MaxHeldRefusalsPerKey) || o["error_code"] != "tlp_refused" {
		t.Fatalf("overflow record %v", o)
	}
	for _, r := range tagged {
		if r["count"] != 1.0 || r["gateway_tag"] == nil || r["aggregated_overflow"] != false {
			t.Fatalf("tagged record %v", r)
		}
	}
}

func TestGatewayRefusalFloodCannotCrowdOutServedRecords(t *testing.T) {
	ss := &stalledSync{release: make(chan struct{})}
	u, err := OpenUsageLogWith(t.TempDir()+"/u.jsonl", UsageOptions{QueueSize: 8, RefusalQueueSize: 4, sync: ss.sync})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	_ = u.Append(UsageRecord{TS: "a", TurnID: "served-0"}) // the writer takes it and stalls
	time.Sleep(50 * time.Millisecond)
	code := "tlp_refused"
	for i := 0; i < 200; i++ { // a flood from 200 keys: far more than the refusal queue holds
		u.AppendRefusal(UsageRecord{TS: "a", Key: fmt.Sprint("k", i), ErrorCode: &code})
	}
	u.releaseRefusals(true)
	for i := 1; i <= 5; i++ {
		_ = u.Append(UsageRecord{TS: "a", TurnID: fmt.Sprint("served-", i)})
	}
	close(ss.release)
	if !u.Flush(5 * time.Second) {
		t.Fatal("flush timed out")
	}
	raw, _ := os.ReadFile(u.path)
	if n := strings.Count(string(raw), `"turn_id":"served-`); n != 6 {
		t.Fatalf("%d of 6 served records written (dropped %d)", n, u.Dropped())
	}
	if u.Dropped() == 0 {
		t.Fatal("the flood overflowed nothing: the test proves nothing")
	}
}
