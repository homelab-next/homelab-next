// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"time"
)

// MaxBodyBytes is the largest request body the gateway reads.
const MaxBodyBytes = 8 << 20

// DefaultUpstreamTimeout bounds one upstream attempt.
const DefaultUpstreamTimeout = 120 * time.Second

// DefaultReserveTokens is the output a call reserves on token and cost limits when neither the
// request (max_tokens, max_completion_tokens) nor the role (max_context_tokens) bounds it.
const DefaultReserveTokens = 4096

// Options configure a Server. Config and Secrets are required.
type Options struct {
	Config  *Config
	Secrets *Secrets
	// Usage receives one record per answered model call; nil keeps none (and /v1/usage is
	// empty).
	Usage *UsageLog
	// Now is the clock for limits and records (time.Now when nil); tests inject one.
	Now func() time.Time
	// UpstreamTimeout bounds one attempt: the whole reply, or for a stream each wait for the
	// next event. DefaultUpstreamTimeout when zero.
	UpstreamTimeout time.Duration
	// LocalClient and CloudClient send to local and cloud deployments; NewUpstreamClient(nil)
	// when nil.
	LocalClient, CloudClient *http.Client
	// ReserveTokens is DefaultReserveTokens when zero (see estimate).
	ReserveTokens int
	// WriteTimeout bounds each write to the caller: a non-streamed reply's whole body, or one
	// streamed event. DefaultWriteTimeout when zero.
	WriteTimeout time.Duration
	// MaxInFlight and MaxInFlightPerKey cap the model calls running at once, in all and per
	// caller key (DefaultMaxInFlight and DefaultMaxInFlightPerKey when zero).
	MaxInFlight, MaxInFlightPerKey int
	// MaxReplyBytesInFlight bounds the bytes all non-streamed replies being read may hold at
	// once (DefaultMaxReplyBytesInFlight when zero); over it the caller gets 503 overloaded.
	MaxReplyBytesInFlight int64
	// MaxReplyBytesInFlightPerKey is one caller key's share of it (a quarter when zero); over
	// its share a key's caller gets 503 overloaded while other keys are served.
	MaxReplyBytesInFlightPerKey int64
	Logger                      *slog.Logger
}

// Server is the gateway's HTTP handler.
type Server struct {
	cfg         *Config
	secrets     *Secrets
	usage       *UsageLog
	now         func() time.Time
	timeout     time.Duration
	localClient *http.Client
	cloudClient *http.Client
	log         *slog.Logger
	limits      *Limiter

	reserveTokens int
	writeTimeout  time.Duration
	inflight      *inFlight
	replies       *replyBudget
}

// New builds a Server.
func New(o Options) *Server {
	s := &Server{cfg: o.Config, secrets: o.Secrets, usage: o.Usage, now: o.Now,
		timeout: o.UpstreamTimeout, localClient: o.LocalClient, cloudClient: o.CloudClient, log: o.Logger,
		reserveTokens: o.ReserveTokens}
	if s.reserveTokens <= 0 {
		s.reserveTokens = DefaultReserveTokens
	}
	s.writeTimeout = o.WriteTimeout
	if s.writeTimeout <= 0 {
		s.writeTimeout = DefaultWriteTimeout
	}
	maxAll, maxKey := o.MaxInFlight, o.MaxInFlightPerKey
	if maxAll <= 0 {
		maxAll = DefaultMaxInFlight
	}
	if maxKey <= 0 {
		maxKey = DefaultMaxInFlightPerKey
	}
	s.inflight = newInFlight(maxAll, maxKey)
	maxReply := o.MaxReplyBytesInFlight
	if maxReply <= 0 {
		maxReply = DefaultMaxReplyBytesInFlight
	}
	s.replies = newReplyBudget(maxReply, o.MaxReplyBytesInFlightPerKey)
	if s.now == nil {
		s.now = time.Now
	}
	if s.timeout <= 0 {
		s.timeout = DefaultUpstreamTimeout
	}
	if s.localClient == nil {
		s.localClient = NewUpstreamClient(nil)
	}
	if s.cloudClient == nil {
		s.cloudClient = NewUpstreamClient(nil)
	}
	if s.log == nil {
		s.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s.limits = NewLimiter(o.Config, s.now)
	return s
}

func (s *Server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	w := newDeadlineWriter(rw, s.writeTimeout)
	switch route := r.Method + " " + r.URL.Path; route {
	case "GET /healthz":
		s.healthz(w)
	case "GET /v1/models", "GET /v1/usage", "POST /v1/chat/completions", "POST /v1/embeddings":
		c := s.secrets.authenticate(r)
		if c == nil {
			errAuth.write(w)
			return
		}
		switch route {
		case "GET /v1/models":
			s.models(w, c)
		case "GET /v1/usage":
			s.usageRange(w, r, c)
		default:
			release, ok := s.inflight.acquire(c.alias())
			if !ok {
				if n := s.inflight.refusals(time.Now()); n > 0 {
					s.log.Warn("calls refused: too many in flight", "refused", n)
				}
				errConcurrency.write(w)
				return
			}
			defer release()
			kind := "chat"
			if route == "POST /v1/embeddings" {
				kind = "embedding"
			}
			s.modelCall(w, r, c, kind)
		}
	default:
		errNotFound.write(w)
	}
}

// healthz is always ok while the process serves; it also carries the counters an operator
// should watch: usage records lost, usage lines /v1/usage reads skipped, and replies refused
// because the in-flight reply budget was spent.
func (s *Server) healthz(w http.ResponseWriter) {
	var dropped, skipped uint64
	if s.usage != nil {
		dropped, skipped = s.usage.Dropped(), s.usage.Skipped()
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "usage_records_dropped": dropped,
		"usage_lines_skipped": skipped, "replies_overloaded": s.replies.refused.Load()})
}

func (s *Server) models(w http.ResponseWriter, c *caller) {
	var ids []string
	switch c.kind {
	case callerTelemetry:
		errRoute.write(w)
		return
	case callerAdmin:
		ids = sortedKeys(s.cfg.Roles)
	default:
		ids = append([]string(nil), c.key.Roles...)
		sort.Strings(ids)
	}
	data := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		data = append(data, map[string]string{"id": id, "object": "model", "owned_by": "hnx"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

func (s *Server) usageRange(w http.ResponseWriter, r *http.Request, c *caller) {
	if c.kind == callerKey {
		errRoute.write(w)
		return
	}
	q := r.URL.Query()
	tag := q.Get("tag")
	if tag != "" && !tagRE.MatchString(tag) {
		badRequest("invalid_tag", "tag is not a gateway tag").write(w)
		return
	}
	start, err1 := strconv.ParseInt(q.Get("start"), 10, 64)
	end, err2 := strconv.ParseInt(q.Get("end"), 10, 64)
	if err1 != nil || err2 != nil || end < start {
		badRequest("invalid_range", "start and end are unix seconds, start <= end").write(w)
		return
	}
	records, truncated := []UsageRecord{}, false
	if s.usage != nil {
		var err error
		// whole seconds: end names the last second included
		records, truncated, err = s.usage.Range(time.Unix(start, 0), time.Unix(end+1, 0), tag)
		if err != nil {
			s.log.Error("usage read failed", "err", err)
			(&apiError{status: 500, message: "the usage log could not be read",
				typ: "server_error", code: "usage_unreadable"}).write(w)
			return
		}
	}
	body := map[string]any{"records": records}
	if truncated {
		body["truncated"] = true
	}
	writeJSON(w, http.StatusOK, body)
}

func newRequestID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "req-" + hex.EncodeToString(b[:])
}
