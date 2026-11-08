// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"encoding/json"
	"log"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/homelab-next/homelab-next/orchestrator/internal/events"
	"github.com/homelab-next/homelab-next/orchestrator/internal/gatewaytag"
	"github.com/homelab-next/homelab-next/orchestrator/internal/inference"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// The job lifecycle events (schemas/events/agent.job.*), published through the store's durable
// outbox in the transaction of the state change each describes (OutboxEventBuilder): started when
// a run starts, failed for a failed or budget_killed run, and finished, the usage record, for every
// run that reaches a terminal state. They carry names, counts, sizes and times only: never a task,
// a prompt, a response or a failure's text.
const (
	EventJobStarted  = "homelabnext.agent.job.started"
	EventJobFinished = "homelabnext.agent.job.finished"
	EventJobFailed   = "homelabnext.agent.job.failed"
)

// JobEventData is the data of agent.job.started and agent.job.failed.
type JobEventData struct {
	RunID    string `json:"run_id"`
	AgentKey string `json:"agent_key"`
	// Attempt is 1 on started; on a terminal event, how many times the attempt chain ran.
	Attempt  int  `json:"attempt"`
	Priority int  `json:"priority"`
	Shadow   bool `json:"shadow"`
	// Outcome and State are the terminal state; empty on started.
	Outcome           string   `json:"outcome,omitempty"`
	QueueWaitSeconds  float64  `json:"queue_wait_seconds"`
	RunSeconds        *float64 `json:"run_seconds,omitempty"`
	TotalSeconds      *float64 `json:"total_seconds,omitempty"`
	LocalAttempts     int      `json:"local_attempts,omitempty"`
	CloudFallbackUsed bool     `json:"cloud_fallback_used"`
	LocalBackendUsed  string   `json:"local_backend_used,omitempty"`
	// RetryOfRunID is the run this one retries; RetriedByRunID the run that retries this one,
	// when it exists as the event is built: on failed, exactly the scheduler's own retry, created
	// in the failing transaction (AutoRetryScheduled). A consumer must not resubmit such a run.
	RetryOfRunID       string `json:"retry_of_run_id,omitempty"`
	RetriedByRunID     string `json:"retried_by_run_id,omitempty"`
	AutoRetryScheduled bool   `json:"auto_retry_scheduled,omitempty"`
	// Resubmits is how many retries precede this run (0: an original submit). Always present.
	Resubmits int    `json:"resubmits"`
	State     string `json:"state,omitempty"`
	// Reason is the failure class on failed, never the failure's text.
	Reason string `json:"reason,omitempty"`
	// ProfileRevisionDrift: a retry that ran another profile revision than its parent.
	ProfileRevisionDrift bool `json:"profile_revision_drift,omitempty"`
}

// TerminalEventTypes lists the events a terminal state publishes, in order: failed and
// budget_killed publish failed, then finished; done and cancelled publish finished only. ok is
// false for a state that is not terminal.
func TerminalEventTypes(s store.State) ([]string, bool) {
	switch s {
	case store.StateDone, store.StateCancelled:
		return []string{EventJobFinished}, true
	case store.StateFailed, store.StateBudgetKilled:
		return []string{EventJobFailed, EventJobFinished}, true
	}
	return nil, false
}

// JobEvent builds agent.job.started or agent.job.failed for j. Its id derives from (type, run id):
// a run has at most one event of each type, and a resend is a duplicate.
func JobEvent(source, eventType string, j *store.Job, at time.Time) events.Event {
	d := JobEventData{
		RunID: j.RunID, AgentKey: j.AgentKey, Attempt: j.Attempts, Priority: j.Priority, Shadow: j.Shadow,
		LocalAttempts: j.LocalAttempts, CloudFallbackUsed: j.CloudFallbackUsed,
		LocalBackendUsed: j.LocalBackendUsed, RetryOfRunID: j.RetryOfRunID,
		RetriedByRunID: j.RetriedByRunID, Resubmits: j.Resubmits,
		ProfileRevisionDrift: j.ProfileRevisionDrift(),
	}
	started := at
	if j.StartedAt != nil {
		started = *j.StartedAt
	}
	if !j.CreatedAt.IsZero() {
		d.QueueWaitSeconds = nonNegSeconds(started.Sub(j.CreatedAt))
	}
	if eventType == EventJobStarted {
		d.Attempt = 1
	} else {
		d.Outcome, d.State = string(j.State), string(j.State)
		if eventType == EventJobFailed {
			d.Reason = j.FailureReason()
			d.AutoRetryScheduled = j.RetriedByRunID != ""
		}
		finished := at
		if j.FinishedAt != nil {
			finished = *j.FinishedAt
		}
		run := nonNegSeconds(finished.Sub(started))
		d.RunSeconds = &run
		if !j.CreatedAt.IsZero() {
			total := nonNegSeconds(finished.Sub(j.CreatedAt))
			d.TotalSeconds = &total
		}
	}
	e := events.New(eventType, source, j.RunID, j.RunID+":"+eventType, at, d)
	e.CorrelationID = j.RunID
	return e
}

func nonNegSeconds(d time.Duration) float64 {
	if d < 0 {
		return 0
	}
	return d.Seconds()
}

// OutboxEventBuilder is the store's event builder (store.EnableOutbox): a row now running yields
// started, a terminal row its TerminalEventTypes. gatewayTagPrefix must be the scheduler's
// (Config.GatewayTagPrefix), so the finished record's gateway_tag is the tag every session of
// the run carried. A failed event is built only for an agent key the schema's slug admits; the
// finished record names any other key as ProfileUnregistered.
func OutboxEventBuilder(source, gatewayTagPrefix string) store.EventBuilder {
	return func(j *store.Job) []store.OutboxEvent {
		types := []string{EventJobStarted}
		if j.State != store.StateRunning {
			t, ok := TerminalEventTypes(j.State)
			if !ok {
				return nil
			}
			types = t
		}
		at := time.Now().UTC()
		var out []store.OutboxEvent
		for _, typ := range types {
			var e events.Event
			switch {
			case typ == EventJobFinished:
				e = JobFinishedEvent(source, gatewayTagPrefix, j, at)
			case typ == EventJobFailed && !isSlug(j.AgentKey, 64):
				log.Printf("queue: run=%s: its agent key is no slug, so no failed event is built for it", j.RunID)
				continue
			default:
				e = JobEvent(source, typ, j, at)
			}
			body, err := json.Marshal(e)
			if err != nil {
				log.Printf("queue: run=%s cannot encode %s: %v", j.RunID, typ, err)
				continue
			}
			out = append(out, store.OutboxEvent{ID: e.ID, Body: body})
		}
		return out
	}
}

// JobGatewayTag is the gateway tag of runID: the one value its sessions carry and its finished
// record names. "" when the run id cannot carry one (such a run never starts a session).
func JobGatewayTag(prefix, runID string) string {
	tag, err := inference.GatewayTag(prefix, runID)
	if err != nil {
		return ""
	}
	return tag
}

// The finished record's outcomes (data.outcome).
const (
	OutcomeCompleted = "completed"
	OutcomeFailed    = "failed"
	OutcomeCancelled = "cancelled"
	OutcomeTimeout   = "timeout"
)

// JobFinishedData is agent.job.finished's data. Every nullable field is present, null meaning
// unknown, which is not 0.
type JobFinishedData struct {
	RunID string `json:"run_id"`
	// Profile is "profile:<agent key>" (a profile is resolved by its agent key), or
	// ProfileUnregistered for a key the schema's profile id cannot hold.
	Profile         string  `json:"profile"`
	ProfileRevision *string `json:"profile_revision"`
	Lane            string  `json:"lane"`
	Outcome         string  `json:"outcome"`
	// FailureClass is the failure class when the outcome is not completed.
	FailureClass       *string `json:"failure_class"`
	RetryOfRunID       *string `json:"retry_of_run_id"`
	AutoRetryScheduled bool    `json:"auto_retry_scheduled"`
	LocalAttempts      int     `json:"local_attempts"`
	CloudFallbackUsed  bool    `json:"cloud_fallback_used"`
	// Backend is the logical backend name that served the run, never a host or URL.
	Backend *string `json:"backend"`
	// Model is the model the run's last attempt asked for (its usage report's).
	Model      *string  `json:"model"`
	QueuedAt   string   `json:"queued_at"`
	StartedAt  *string  `json:"started_at"`
	FinishedAt string   `json:"finished_at"`
	QueueWaitS *float64 `json:"queue_wait_s"`
	WallS      *float64 `json:"wall_s"`
	// InputBytes is the task's size as received; OutputBytes the stored answer's (null: none).
	InputBytes  int           `json:"input_bytes"`
	OutputBytes *int          `json:"output_bytes"`
	Usage       *JobUsageData `json:"usage"`
	// TurnExitReason is the token of the report's turn_exit_reason (TurnExitToken).
	TurnExitReason *string     `json:"turn_exit_reason"`
	Tools          []ToolCalls `json:"tools,omitempty"`
	GatewayTag     string      `json:"gateway_tag"`
}

// JobUsageData is the usage counters, summed over the run's sessions; nil is unknown.
type JobUsageData struct {
	InputTokens     *int     `json:"input_tokens"`
	OutputTokens    *int     `json:"output_tokens"`
	ReasoningTokens *int     `json:"reasoning_tokens"`
	CacheReadTokens *int     `json:"cache_read_tokens"`
	APICalls        *int     `json:"api_calls"`
	CostUSD         *float64 `json:"cost_usd"`
}

// ToolCalls is one tools entry; the controller has no tool counts yet, so it sends none.
type ToolCalls struct {
	Name  string `json:"name"`
	Calls int    `json:"calls"`
}

// JobOutcome maps a terminal row to its outcome: a failure the controller classed as a spent
// time budget (timeout, deadline, budget) is timeout; budget_killed and every other failure are
// failed. ok is false for a state that is not terminal.
func JobOutcome(j *store.Job) (string, bool) {
	switch j.State {
	case store.StateDone:
		return OutcomeCompleted, true
	case store.StateCancelled:
		return OutcomeCancelled, true
	case store.StateBudgetKilled:
		return OutcomeFailed, true
	case store.StateFailed:
		switch j.FailureClass {
		case store.FailureTimeout, store.FailureDeadline, store.FailureBudget:
			return OutcomeTimeout, true
		}
		return OutcomeFailed, true
	}
	return "", false
}

// ProfileUnregistered names, in the finished record, a run whose agent key the schema's profile
// id cannot hold.
const ProfileUnregistered = "profile:unregistered"

const (
	maxProfileIDLen  = 128
	maxLocalAttempts = 1000
	maxModelLen      = 512
)

// JobFinishedEvent builds agent.job.finished for the terminal row j. Every value the controller
// does not fully control is checked against the schema's rule and sent as null (or, for the
// required profile, ProfileUnregistered) when it does not fit; the row keeps the raw value.
func JobFinishedEvent(source, gatewayTagPrefix string, j *store.Job, at time.Time) events.Event {
	outcome, _ := JobOutcome(j)
	lane := "real"
	if j.Shadow {
		lane = "shadow"
	}
	finished := at.UTC()
	if j.FinishedAt != nil {
		finished = j.FinishedAt.UTC()
	}
	d := JobFinishedData{
		RunID:              j.RunID,
		Profile:            eventProfile(j.AgentKey),
		ProfileRevision:    orNull(j.ProfileRevision, isRevision),
		Lane:               lane,
		Outcome:            outcome,
		RetryOfRunID:       orNull(j.RetryOfRunID, gatewaytag.ValidRunID),
		AutoRetryScheduled: j.State != store.StateDone && j.RetriedByRunID != "",
		LocalAttempts:      min(max(j.LocalAttempts, 0), maxLocalAttempts),
		CloudFallbackUsed:  j.CloudFallbackUsed,
		Backend:            orNull(j.LocalBackendUsed, isBackendName),
		Model:              orNull(j.Model, isModelName),
		QueuedAt:           formatTime(j.CreatedAt),
		FinishedAt:         formatTime(finished),
		InputBytes:         len(j.TaskDescription),
		TurnExitReason:     orNull(TurnExitToken(j.TurnExitReason), func(s string) bool { return s != "" }),
		GatewayTag:         JobGatewayTag(gatewayTagPrefix, j.RunID),
	}
	if outcome != OutcomeCompleted {
		fc := j.FailureReason()
		if !isFailureClass(fc) {
			fc = store.FailureUnknown
		}
		d.FailureClass = &fc
	}
	if j.StartedAt != nil {
		s := formatTime(*j.StartedAt)
		d.StartedAt = &s
		wall := nonNegSeconds(finished.Sub(*j.StartedAt))
		d.WallS = &wall
		if !j.CreatedAt.IsZero() {
			wait := nonNegSeconds(j.StartedAt.Sub(j.CreatedAt))
			d.QueueWaitS = &wait
		}
	}
	if j.ResponseBody != "" {
		n := len(j.ResponseBody)
		d.OutputBytes = &n
	}
	if u := j.Usage; u.Known() {
		d.Usage = &JobUsageData{
			InputTokens: count(u.InputTokens), OutputTokens: count(u.OutputTokens), ReasoningTokens: count(u.ReasoningTokens),
			CacheReadTokens: count(u.CacheReadTokens), APICalls: count(u.APICalls), CostUSD: cost(u.CostUSD),
		}
	}
	e := events.New(EventJobFinished, source, j.RunID, j.RunID+":"+EventJobFinished, at, d)
	e.CorrelationID = j.RunID
	return e
}

// eventProfile is "profile:<agent key>" when the key is a slug short enough for a profile id.
func eventProfile(agentKey string) string {
	if isSlug(agentKey, maxProfileIDLen-len("profile:")) {
		return "profile:" + agentKey
	}
	return ProfileUnregistered
}

// TurnExitToken is the event form of a report's turn_exit_reason: the token before any "(",
// trimmed, when it fits the schema's pattern, else "". The text after it can carry an error's
// text (a URL, a token), so it is never sent.
func TurnExitToken(raw string) string {
	tok, _, _ := strings.Cut(raw, "(")
	tok = strings.TrimSpace(tok)
	if len(tok) == 0 || len(tok) > 64 || !isAlnum(tok[0]) || !allIn(tok, "._-") {
		return ""
	}
	return tok
}

// The schema's value rules, written out by hand (no regular expression in this package). Each is
// the rule exactly, but for isModelName, which is stricter: it refuses some names the schema
// accepts, never one it refuses.

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// allIn reports whether every byte of s is a letter, a digit or in extra.
func allIn(s, extra string) bool {
	for i := 0; i < len(s); i++ {
		if !isAlnum(s[i]) && strings.IndexByte(extra, s[i]) < 0 {
			return false
		}
	}
	return true
}

// isSlug is ^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$ of at most max bytes.
func isSlug(s string, max int) bool {
	if s == "" || len(s) > max || s[0] < 'a' || s[0] > 'z' || s[len(s)-1] == '-' || strings.Contains(s, "--") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// isRevision is ^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$.
func isRevision(s string) bool {
	return len(s) >= 1 && len(s) <= 64 && isAlnum(s[0]) && allIn(s, "._:-")
}

// isFailureClass is ^[a-z][a-z0-9-]{0,39}$.
func isFailureClass(s string) bool {
	if len(s) < 1 || len(s) > 40 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// isBackendName is ^[A-Za-z0-9._-]{1,64}$.
func isBackendName(s string) bool { return len(s) >= 1 && len(s) <= 64 && allIn(s, "._-") }

// isModelName is an opaque model name the schema's model rule accepts: 1 to 512 of
// [A-Za-z0-9._:/@-], starting with a letter, a digit, "/" or ".", with no "..". It refuses
// anything that could be a URL, an address or a mail address: "://" or ":/" after the second
// character, any "@", ":" followed by a port and "/", and four dot-separated digit groups (an
// IPv4 address) anywhere.
func isModelName(s string) bool {
	if len(s) < 1 || len(s) > maxModelLen || !utf8.ValidString(s) || !allIn(s, "._:/@-") {
		return false
	}
	if c := s[0]; !isAlnum(c) && c != '/' && c != '.' {
		return false
	}
	if strings.Contains(s, "..") || strings.Contains(s, "@") || len(s) > 2 && strings.Contains(s[2:], ":/") {
		return false
	}
	if hasPortPath(s) || hasDottedQuad(s) {
		return false
	}
	return true
}

// hasPortPath reports whether s holds ":" followed by 2 to 5 digits and "/".
func hasPortPath(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != ':' {
			continue
		}
		j := i + 1
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if n := j - i - 1; n >= 2 && n <= 5 && j < len(s) && s[j] == '/' {
			return true
		}
	}
	return false
}

// hasDottedQuad reports whether s holds four dot-separated groups of 1 to 3 digits.
func hasDottedQuad(s string) bool {
	for i := 0; i < len(s); i++ {
		j, groups := i, 0
		for groups < 4 {
			k := j
			for k < len(s) && k-j < 3 && s[k] >= '0' && s[k] <= '9' {
				k++
			}
			if k == j {
				break
			}
			groups++
			j = k
			if groups < 4 {
				if j >= len(s) || s[j] != '.' {
					break
				}
				j++
			}
		}
		if groups == 4 {
			return true
		}
	}
	return false
}

func orNull(s string, valid func(string) bool) *string {
	if !valid(s) {
		return nil
	}
	return &s
}

// count is a counter for the event: a negative one (impossible, so unknown) is null.
func count(n *int) *int {
	if n == nil || *n < 0 {
		return nil
	}
	return n
}

// cost is the cost for the event: negative, NaN or infinite is null.
func cost(f *float64) *float64 {
	if f == nil || *f < 0 || math.IsNaN(*f) || math.IsInf(*f, 0) {
		return nil
	}
	return f
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
