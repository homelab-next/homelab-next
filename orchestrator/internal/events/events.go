// SPDX-License-Identifier: Apache-2.0

// Package events publishes the controller's lifecycle events to an HTTP event forwarder under
// this repository's forwarder contract (docs/events.md): a CloudEvents 1.0 structured-mode JSON
// envelope (schemas/events/envelope.schema.json), POSTed with Content-Type
// application/cloudevents+json and an Idempotency-Key header equal to the event id. The id is a
// pure function of the event's identity (DeriveID), so a resend after a lost acknowledgement is a
// harmless duplicate at the forwarder.
//
// Two senders share one wire contract. OutboxSender (outbox.go) drains a durable outbox that the
// store fills in the same transaction as the job's state change, so an event survives a crash or
// a restart; it is the one a controller runs. HTTPPublisher is an in-memory queue: Publish never
// blocks, and events still queued when the process dies are lost. Both send in order and classify
// the forwarder's answer as the contract does: a transient failure (network, 408, 425, 429, 5xx)
// and an answer that blames the configuration (401, 403, 404, 421, or a redirect, which is never
// followed) are retried with bounded exponential backoff, so a durable event stays pending until
// the URL or the credential is fixed; a permanent refusal (any other 4xx, a 409 id collision
// included) is logged and dropped, never retried into success.
package events

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	// ContentType is the media type of a structured-mode CloudEvents envelope.
	ContentType = "application/cloudevents+json"
	// IdempotencyHdr carries the event id on every POST.
	IdempotencyHdr = "Idempotency-Key"
	// DefaultSource is the controller's source when its configuration names none. It names no
	// product (docs/orchestration-controller.md, "Neutral names").
	DefaultSource   = "svc:orchestrator"
	defaultQueue    = 1024
	defaultAttempts = 8
)

// Event is the CloudEvents 1.0 structured-mode envelope.
type Event struct {
	SpecVersion   string `json:"specversion"`
	ID            string `json:"id"`
	Source        string `json:"source"`
	Type          string `json:"type"`
	Time          string `json:"time"`
	Subject       string `json:"subject,omitempty"`
	CorrelationID string `json:"correlationid,omitempty"`
	Data          any    `json:"data"`
}

// svcID is the logical-id pattern of a svc: source (schemas/ids/logical-id.schema.json, svc_id;
// a test holds the two equal).
var svcID = regexp.MustCompile(`^svc:[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)

// ValidSource reports whether s is a valid envelope source of the svc: kind.
func ValidSource(s string) bool { return svcID.MatchString(s) && len(s) <= 128 }

// DeriveID is the Go side of homelabnext.events.envelope.derive_event_id: "evt-" and the first 32
// hex characters of the SHA-256 of the JSON array [type, source, subject, dedupeKey], encoded
// with compact separators and every non-ASCII character escaped (\uXXXX, a surrogate pair above
// the BMP), as Python's json.dumps(ensure_ascii=True) writes it. Same inputs, same id, on every
// host, every resend and in both languages.
func DeriveID(eventType, source, subject, dedupeKey string) string {
	sum := sha256.Sum256(asciiJSON([]string{eventType, source, subject, dedupeKey}))
	return "evt-" + hex.EncodeToString(sum[:])[:32]
}

// asciiJSON encodes v as compact JSON with no HTML escaping (Python does not escape <, > or &)
// and with every non-ASCII rune escaped. encoding/json already escapes U+2028 and U+2029 and
// writes invalid UTF-8 as U+FFFD; the rest it leaves as UTF-8, which is escaped here.
func asciiJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v) // a []string always encodes
	raw := bytes.TrimRight(buf.Bytes(), "\n")
	out := make([]byte, 0, len(raw))
	for len(raw) > 0 {
		r, size := utf8.DecodeRune(raw)
		switch {
		case r < utf8.RuneSelf:
			out = append(out, raw[0])
		case r > 0xffff:
			hi, lo := utf16.EncodeRune(r)
			out = fmt.Appendf(out, `\u%04x\u%04x`, hi, lo)
		default:
			out = fmt.Appendf(out, `\u%04x`, r)
		}
		raw = raw[size:]
	}
	return out
}

// New builds an envelope whose id is derived from (type, source, subject, dedupeKey). A nil data
// becomes an empty object: the envelope requires data to be one.
func New(eventType, source, subject, dedupeKey string, at time.Time, data any) Event {
	if data == nil {
		data = map[string]any{}
	}
	return Event{
		SpecVersion: "1.0",
		ID:          DeriveID(eventType, source, subject, dedupeKey),
		Source:      source,
		Type:        eventType,
		Time:        at.UTC().Format(time.RFC3339Nano),
		Subject:     subject,
		Data:        data,
	}
}

// Stats are a sender's lifetime counters (exposed as metrics).
type Stats struct {
	Published uint64 // acknowledged by the forwarder, duplicates included
	Rejected  uint64 // refused for good by the forwarder
	Failed    uint64 // given up after the retry budget (HTTPPublisher) or retried (OutboxSender)
	Dropped   uint64 // never sent: the queue or the outbox was full
}

// Config configures a sender.
type Config struct {
	URL         string
	BearerToken string // optional; sent as Authorization: Bearer
	QueueSize   int    // <= 0: 1024
	MaxAttempts int    // <= 0: 8
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	Timeout     time.Duration // per POST; <= 0: 5s
	HTTP        *http.Client
}

// HTTPPublisher sends events to a forwarder URL from one background worker.
type HTTPPublisher struct {
	cfg     Config
	ch      chan Event
	done    chan struct{}
	stop    chan struct{}
	once    sync.Once
	closing atomic.Bool
	// mu guards ch against a Publish racing Close's close(ch): Publish holds it shared, Close
	// exclusively
	mu sync.RWMutex

	published, rejected, failed, dropped atomic.Uint64
}

// NewHTTPPublisher validates cfg and starts the worker. A bearer token over plain http to a host
// that is not loopback is refused (the rule homelabnext.events.forwarder.HttpForwarder applies too), so a
// credential never crosses the network in clear.
func NewHTTPPublisher(cfg Config) (*HTTPPublisher, error) {
	cfg, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	p := &HTTPPublisher{cfg: cfg, ch: make(chan Event, cfg.QueueSize), done: make(chan struct{}), stop: make(chan struct{})}
	go p.run()
	return p, nil
}

// normalizeConfig validates cfg and fills its defaults; both senders use it.
func normalizeConfig(cfg Config) (Config, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return cfg, fmt.Errorf("events forwarder url %q must be an absolute http(s) URL", cfg.URL)
	}
	if cfg.BearerToken != "" && u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return cfg, fmt.Errorf("events forwarder url %q: refusing to send a bearer token over plain http to a non-loopback host", cfg.URL)
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaultQueue
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultAttempts
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = time.Second
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = time.Minute
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{
			Timeout: cfg.Timeout,
			// never follow a redirect: the body and the token are for this URL only
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return cfg, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Publish queues e without blocking. A full queue drops e and counts it.
func (p *HTTPPublisher) Publish(e Event) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closing.Load() {
		p.dropped.Add(1)
		return
	}
	select {
	case p.ch <- e:
	default:
		p.dropped.Add(1)
		log.Printf("events: queue full (%d), dropped %s %s", p.cfg.QueueSize, e.Type, e.Subject)
	}
}

// Close stops accepting events, gives each queued one a single attempt (no retries), and waits
// until they are sent or ctx ends.
func (p *HTTPPublisher) Close(ctx context.Context) {
	p.once.Do(func() {
		p.mu.Lock()
		p.closing.Store(true)
		close(p.stop)
		close(p.ch)
		p.mu.Unlock()
	})
	select {
	case <-p.done:
	case <-ctx.Done():
		log.Printf("events: shutdown before every queued event was sent")
	}
}

// Stats returns the lifetime counters.
func (p *HTTPPublisher) Stats() Stats {
	return Stats{Published: p.published.Load(), Rejected: p.rejected.Load(), Failed: p.failed.Load(), Dropped: p.dropped.Load()}
}

func (p *HTTPPublisher) run() {
	defer close(p.done)
	for e := range p.ch {
		p.deliver(e)
	}
}

type outcome int

const (
	accepted outcome = iota
	transient
	// misconfigured: the forwarder blames the URL or the credential. It is retried like a
	// transient failure, so a durable event waits for the fix instead of being dropped.
	misconfigured
	permanent
)

func (p *HTTPPublisher) deliver(e Event) {
	body, err := json.Marshal(e)
	if err != nil {
		p.rejected.Add(1)
		log.Printf("events: cannot encode %s %s: %v", e.Type, e.Subject, err)
		return
	}
	backoff := p.cfg.BaseBackoff
	for attempt := 1; ; attempt++ {
		res, detail := post(p.cfg, e.ID, body)
		switch res {
		case accepted:
			p.published.Add(1)
			return
		case permanent:
			p.rejected.Add(1)
			log.Printf("events: forwarder refused %s %s (id %s): %s", e.Type, e.Subject, e.ID, detail)
			return
		}
		if attempt >= p.cfg.MaxAttempts || p.closing.Load() {
			p.failed.Add(1)
			log.Printf("events: giving up on %s %s (id %s) after %d attempt(s): %s", e.Type, e.Subject, e.ID, attempt, detail)
			return
		}
		select {
		case <-time.After(backoff):
		case <-p.stop:
		}
		backoff = min(backoff*2, p.cfg.MaxBackoff)
	}
}

// post sends one envelope and classifies the answer.
func post(cfg Config, id string, body []byte) (outcome, string) {
	req, err := http.NewRequest(http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return permanent, err.Error()
	}
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set(IdempotencyHdr, id)
	if cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.BearerToken)
	}
	resp, err := cfg.HTTP.Do(req)
	if err != nil {
		return transient, "forwarder unreachable: " + err.Error()
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	res := classify(resp.StatusCode)
	if res == misconfigured {
		return res, resp.Status + " (the forwarder blames the configuration: check its URL and credential)"
	}
	return res, resp.Status
}

// classify maps a forwarder status to the contract's outcomes (docs/events.md, "Forwarder
// contract"). A redirect counts as a configuration fault: the body and the token are for the
// configured URL only, so it is never followed.
func classify(code int) outcome {
	switch {
	case code == 200 || code == 201 || code == 202 || code == 204:
		return accepted
	case code == 408 || code == 425 || code == 429 || code >= 500:
		return transient
	case code == 401 || code == 403 || code == 404 || code == 421 || (code >= 300 && code < 400):
		return misconfigured
	default:
		return permanent
	}
}
