// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// OutboxRecord is one undelivered event in a durable outbox.
type OutboxRecord struct {
	Seq      int64  // delivery order
	ID       string // event id (the Idempotency-Key)
	Body     []byte // the JSON envelope, exactly as it is POSTed
	Attempts int
}

// Outbox is durable event storage (the controller's store implements it). The store itself
// enqueues an event, in the same transaction as the state change it describes; the sender only
// reads, acknowledges and counts attempts.
type Outbox interface {
	PendingEvents(limit int) ([]OutboxRecord, error)
	AckEvent(seq int64) error
	MarkEventAttempt(seq int64) error
	// OutboxDropped counts events dropped because the outbox was full.
	OutboxDropped() uint64
}

// OutboxSender drains an Outbox to the forwarder in Seq order. A transient failure, or an answer
// that blames the configuration, holds the head of the line and retries it with exponential
// backoff (cfg.BaseBackoff doubling up to cfg.MaxBackoff) for as long as it takes: the outbox is
// durable, so giving up would lose exactly what it exists to keep, and its size bound (with
// counted drops) is what limits a long outage. A permanent refusal is acknowledged (dropped) and
// counted as rejected.
type OutboxSender struct {
	cfg   Config
	ob    Outbox
	poll  time.Duration
	nudge chan struct{}
	stop  chan struct{}
	done  chan struct{}
	once  sync.Once

	published, rejected, failed atomic.Uint64
}

// NewOutboxSender validates cfg (normalizeConfig) and starts the worker. poll <= 0
// means 1s; Nudge wakes the worker sooner.
func NewOutboxSender(cfg Config, ob Outbox, poll time.Duration) (*OutboxSender, error) {
	cfg, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	if poll <= 0 {
		poll = time.Second
	}
	s := &OutboxSender{cfg: cfg, ob: ob, poll: poll, nudge: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go s.run()
	return s, nil
}

// Nudge tells the worker an event was enqueued. It never blocks.
func (s *OutboxSender) Nudge() {
	select {
	case s.nudge <- struct{}{}:
	default:
	}
}

// Close stops the worker after its current send, waiting until it has stopped or ctx ends.
// Undelivered events stay in the outbox for the next start.
func (s *OutboxSender) Close(ctx context.Context) {
	s.once.Do(func() { close(s.stop) })
	select {
	case <-s.done:
	case <-ctx.Done():
		log.Printf("events: shutdown while a delivery was in flight; it stays in the outbox")
	}
}

// Stats returns the lifetime counters. Failed counts delivery attempts that failed and will be
// retried; Dropped is the outbox's own overflow count.
func (s *OutboxSender) Stats() Stats {
	return Stats{Published: s.published.Load(), Rejected: s.rejected.Load(), Failed: s.failed.Load(), Dropped: s.ob.OutboxDropped()}
}

func (s *OutboxSender) run() {
	defer close(s.done)
	backoff := s.cfg.BaseBackoff
	for {
		wait := s.poll
		if held := s.drain(); held {
			wait = backoff
			backoff = min(backoff*2, s.cfg.MaxBackoff)
		} else {
			backoff = s.cfg.BaseBackoff
		}
		t := time.NewTimer(wait)
		select {
		case <-s.stop:
			t.Stop()
			return
		case <-s.nudge:
			t.Stop()
		case <-t.C:
		}
	}
}

// drain sends pending events in order until the outbox is empty or a send fails without a
// permanent refusal (held: retry it after the backoff).
func (s *OutboxSender) drain() (held bool) {
	for {
		select {
		case <-s.stop:
			return false
		default:
		}
		recs, err := s.ob.PendingEvents(64)
		if err != nil {
			log.Printf("events: read outbox: %v", err)
			return true
		}
		if len(recs) == 0 {
			return false
		}
		for _, r := range recs {
			res, detail := post(s.cfg, r.ID, r.Body)
			switch res {
			case accepted:
				s.published.Add(1)
			case permanent:
				s.rejected.Add(1)
				log.Printf("events: forwarder refused %s: %s -- dropped", r.ID, detail)
			default: // transient or misconfigured: hold the line
				s.failed.Add(1)
				if err := s.ob.MarkEventAttempt(r.Seq); err != nil {
					log.Printf("events: record attempt for %s: %v", r.ID, err)
				}
				if r.Attempts == 0 || (r.Attempts+1)%10 == 0 {
					log.Printf("events: delivery of %s failed (attempt %d), will retry: %s", r.ID, r.Attempts+1, detail)
				}
				return true
			}
			if err := s.ob.AckEvent(r.Seq); err != nil {
				log.Printf("events: ack %s: %v", r.ID, err)
				return true
			}
		}
	}
}
