// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type memOutbox struct {
	mu   sync.Mutex
	recs []OutboxRecord
}

func (m *memOutbox) PendingEvents(limit int) ([]OutboxRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]OutboxRecord(nil), m.recs[:min(limit, len(m.recs))]...), nil
}

func (m *memOutbox) AckEvent(seq int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, r := range m.recs {
		if r.Seq == seq {
			m.recs = append(m.recs[:i], m.recs[i+1:]...)
			break
		}
	}
	return nil
}

func (m *memOutbox) MarkEventAttempt(seq int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.recs {
		if m.recs[i].Seq == seq {
			m.recs[i].Attempts++
		}
	}
	return nil
}

func (m *memOutbox) OutboxDropped() uint64 { return 7 }

func (m *memOutbox) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.recs)
}

func closeOutbox(s *OutboxSender) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Close(ctx)
}

// The outbox sender delivers in order, holds the head of the line across transient failures and
// configuration answers (it never gives up on a durable event), drops a permanent refusal, and
// sends the envelope with its content type, the bearer token and the event id as the
// Idempotency-Key.
func TestOutboxSender_OrderRetriesAndRefusals(t *testing.T) {
	f := &fakeForwarder{statuses: []int{503, 403, 307, 202, 400, 202}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	ob := &memOutbox{}
	for i, id := range []string{"evt-a", "evt-b", "evt-c"} {
		ob.recs = append(ob.recs, OutboxRecord{Seq: int64(i + 1), ID: id, Body: []byte(`{"id":"` + id + `"}`)})
	}
	s, err := NewOutboxSender(Config{URL: srv.URL, BearerToken: "tok", BaseBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond}, ob, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return ob.len() == 0 })
	closeOutbox(s)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.got) != 2 || f.got[0]["id"] != "evt-a" || f.got[1]["id"] != "evt-c" {
		t.Fatalf("forwarder accepted %v, want evt-a then evt-c (evt-b refused)", f.got)
	}
	if h := f.headers[0]; h.Get(IdempotencyHdr) != "evt-a" || h.Get("Content-Type") != ContentType || h.Get("Authorization") != "Bearer tok" {
		t.Errorf("headers = %v", h)
	}
	st := s.Stats()
	if st.Published != 2 || st.Rejected != 1 || st.Failed != 3 || st.Dropped != 7 {
		t.Errorf("stats = %+v, want published 2, rejected 1, failed (retried) 3, dropped (the outbox's) 7", st)
	}
}

// Nudge wakes the sender without waiting for its poll interval.
func TestOutboxSender_Nudge(t *testing.T) {
	f := &fakeForwarder{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	ob := &memOutbox{}
	s, err := NewOutboxSender(Config{URL: srv.URL}, ob, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer closeOutbox(s)
	time.Sleep(20 * time.Millisecond) // the first (empty) pass is done; it now waits an hour
	ob.mu.Lock()
	ob.recs = append(ob.recs, OutboxRecord{Seq: 1, ID: "evt-n", Body: []byte(`{}`)})
	ob.mu.Unlock()
	s.Nudge()
	waitFor(t, func() bool { return ob.len() == 0 })
}

func TestNewOutboxSender_ValidatesConfig(t *testing.T) {
	if _, err := NewOutboxSender(Config{URL: "http://events.example.internal/ingest", BearerToken: "x"}, &memOutbox{}, 0); err == nil {
		t.Error("accepted a bearer token over plain http to a remote host")
	}
}
