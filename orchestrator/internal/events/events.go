// SPDX-License-Identifier: Apache-2.0

// Package events publishes the controller's lifecycle events to an HTTP event forwarder under
// this repository's forwarder contract (docs/events.md): a CloudEvents 1.0 structured-mode JSON
// envelope (schemas/events/envelope.schema.json), POSTed with Content-Type
// application/cloudevents+json and an Idempotency-Key header equal to the event id. The id is a
// pure function of the event's identity (DeriveID), so a resend after a lost acknowledgement is a
// harmless duplicate at the forwarder.
//
// The sender, OutboxSender (outbox.go), drains a durable outbox that the store fills in the same
// transaction as the job's state change, so an event survives a crash or a restart. It sends in
// order and classifies the forwarder's answer by the forwarder contract: a transient failure
// (network, 408, 425, 429, 5xx) and an answer that blames the configuration (401, 403, 404, 421,
// and a 3xx, since this sender follows no redirect) are retried with bounded exponential
// backoff, so the event stays pending until the URL or the credential is fixed; a permanent
// refusal (any other 4xx, a 409 id collision included) is logged and dropped, never retried into
// success.
package events

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
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
	DefaultSource = "svc:orchestrator"
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
// with compact separators and DEL and every non-ASCII character escaped (\uXXXX, a surrogate pair
// above the BMP), as Python's json.dumps(ensure_ascii=True) writes it. Same inputs, same id, on every
// host, every resend and in both languages.
func DeriveID(eventType, source, subject, dedupeKey string) string {
	sum := sha256.Sum256(asciiJSON([]string{eventType, source, subject, dedupeKey}))
	return "evt-" + hex.EncodeToString(sum[:])[:32]
}

// asciiJSON encodes v as compact JSON with no HTML escaping (Python does not escape <, > or &)
// and with DEL and every non-ASCII rune escaped. encoding/json already escapes U+2028 and U+2029 and
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
		case r == 0x7f:
			out = append(out, `\u007f`...) // Python escapes DEL too; encoding/json does not
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

// New builds an envelope whose id is derived from (type, source, subject, dedupeKey). A nil data,
// typed nils (a nil map, pointer, slice or interface) included, becomes an empty object: the
// envelope requires data to be one.
func New(eventType, source, subject, dedupeKey string, at time.Time, data any) Event {
	if isNil(data) {
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

// isNil reports whether v is nil or a typed nil that would encode as JSON null.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Map, reflect.Pointer, reflect.Slice, reflect.Interface, reflect.Func, reflect.Chan:
		return rv.IsNil()
	}
	return false
}

// Stats are the sender's lifetime counters (exposed as metrics).
type Stats struct {
	Published uint64 // acknowledged by the forwarder, duplicates included
	Rejected  uint64 // refused for good by the forwarder
	Failed    uint64 // delivery attempts that failed and will be retried
	Dropped   uint64 // never sent: the outbox was full
}

// maxBackoff bounds the configurable backoff: a sender that waits longer than this between
// attempts leaves events pending for no reason an operator would choose.
const maxBackoff = time.Hour

// Config configures the sender.
type Config struct {
	URL         string
	BearerToken string        // optional; sent as Authorization: Bearer
	BaseBackoff time.Duration // 0: 1s
	MaxBackoff  time.Duration // 0: 1m; BaseBackoff <= MaxBackoff <= 1h
	Timeout     time.Duration // per POST; 0: 5s
	// HTTP, when set, is copied: the copy never follows a redirect and gets Timeout when it has
	// none, whatever the caller's client says.
	HTTP *http.Client
}

// normalizeConfig validates cfg and fills its defaults. A credential (a bearer token, or userinfo
// in the URL) over plain http to a host that is not loopback is refused (the rule
// homelabnext.events.forwarder.HttpForwarder applies too), so it never crosses the network in
// clear. Errors name the URL without its userinfo, query or fragment.
func normalizeConfig(cfg Config) (Config, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return cfg, errors.New("events forwarder url is not a valid URL")
	}
	shown := redacted(u)
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return cfg, fmt.Errorf("events forwarder url %q must be an absolute http(s) URL", shown)
	}
	if (cfg.BearerToken != "" || u.User != nil) && u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return cfg, fmt.Errorf("events forwarder url %q: refusing to send a credential over plain http to a non-loopback host", shown)
	}
	for _, d := range []time.Duration{cfg.BaseBackoff, cfg.MaxBackoff, cfg.Timeout} {
		if d < 0 {
			return cfg, fmt.Errorf("events forwarder: negative backoff or timeout %v", d)
		}
	}
	if cfg.BaseBackoff == 0 {
		cfg.BaseBackoff = time.Second
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = time.Minute
	}
	if cfg.BaseBackoff > cfg.MaxBackoff || cfg.MaxBackoff > maxBackoff {
		return cfg, fmt.Errorf("events forwarder: backoff must satisfy 0 < base (%v) <= max (%v) <= %v", cfg.BaseBackoff, cfg.MaxBackoff, maxBackoff)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	var c http.Client
	if cfg.HTTP != nil {
		c = *cfg.HTTP
	}
	// never follow a redirect: the body and the credential are for the configured URL only
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if c.Timeout == 0 {
		c.Timeout = cfg.Timeout
	}
	cfg.HTTP = &c
	return cfg, nil
}

// redacted is u without its query and fragment, its password masked (url.URL.Redacted).
func redacted(u *url.URL) string {
	c := *u
	c.RawQuery, c.ForceQuery, c.Fragment, c.RawFragment = "", false, "", ""
	return c.Redacted()
}

// scrubURL is err's text with the configured URL shown redacted. net/http's errors quote the
// request URL with its query, which can carry a credential, and the sender logs the detail. Only
// the URL's own spellings are replaced, and its query, fragment and password only where they
// still stand in URL position (after "?", "#", or between ":" and "@"), so the rest of the
// message is never rewritten, however short the query.
func scrubURL(err error, raw string) string {
	msg := err.Error()
	u, perr := url.Parse(raw)
	if perr != nil {
		return "the events forwarder url is not a valid URL"
	}
	shown := redacted(u)
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		msg = ue.Op + " " + strconv.Quote(shown) + ": " + ue.Err.Error()
	}
	bare := *u
	bare.User = nil
	for _, whole := range []string{raw, u.String(), u.Redacted(), bare.String()} {
		msg = strings.ReplaceAll(msg, whole, shown)
	}
	var parts []string
	if u.RawQuery != "" {
		parts = append(parts, "?"+u.RawQuery)
	}
	if u.Fragment != "" {
		parts = append(parts, "#"+u.EscapedFragment(), "#"+u.Fragment)
	}
	if pw, ok := u.User.Password(); ok && pw != "" {
		parts = append(parts, ":"+pw+"@")
	}
	for _, p := range parts {
		repl := "?[redacted]"
		switch p[0] {
		case '#':
			repl = "#[redacted]"
		case ':':
			repl = ":***@"
		}
		msg = strings.ReplaceAll(msg, p, repl)
	}
	return msg
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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

// post sends one envelope and classifies the answer.
func post(cfg Config, id string, body []byte) (outcome, string) {
	req, err := http.NewRequest(http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return permanent, scrubURL(err, cfg.URL)
	}
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set(IdempotencyHdr, id)
	if cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.BearerToken)
	}
	resp, err := cfg.HTTP.Do(req)
	if err != nil {
		return transient, "forwarder unreachable: " + scrubURL(err, cfg.URL)
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
