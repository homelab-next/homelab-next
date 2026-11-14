// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"encoding/json"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/events"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner/runnertest"
	"github.com/homelab-next/homelab-next/orchestrator/internal/schematest"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

func ip(n int) *int             { return &n }
func fp(f float64) *float64     { return &f }
func tp(t time.Time) *time.Time { return &t }

var (
	t0 = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	t1 = t0.Add(30 * time.Second)
	t2 = t1.Add(90 * time.Second)
)

// outboxEvents returns runID's pending events by type, decoded.
func outboxEvents(t *testing.T, st *store.Store, runID string) map[string]map[string]any {
	t.Helper()
	recs, err := st.PendingEvents(1000)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, rec := range recs {
		var e map[string]any
		if err := json.Unmarshal(rec.Body, &e); err != nil {
			t.Fatal(err)
		}
		if e["subject"] == runID {
			out[e["type"].(string)] = e
		}
	}
	return out
}

func outboxEvent(t *testing.T, st *store.Store, runID, typ string) map[string]any {
	t.Helper()
	e, ok := outboxEvents(t, st, runID)[typ]
	if !ok {
		t.Fatalf("no %s for %s in the outbox", typ, runID)
	}
	return e
}

var validator = func() *schematest.Validator {
	v, err := schematest.Load("../../../schemas")
	if err != nil {
		panic(err)
	}
	return v
}()

// assertFits validates e against its type's schema and the envelope, in place.
func assertFits(t *testing.T, e any, stems ...string) {
	t.Helper()
	for _, stem := range append([]string{"envelope"}, stems...) {
		r, err := validator.ValidateStem(stem, e)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Unsupported) > 0 || len(r.Errs) > 0 {
			b, _ := json.Marshal(e)
			t.Fatalf("%s refuses %s\nerrors: %v\nunsupported: %v", stem, b, r.Errs, r.Unsupported)
		}
	}
}

// doneJob is a finished row with every field set.
func doneJob() *store.Job {
	return &store.Job{
		RunID: "0123abcd", AgentKey: "watcher", ProfileRevision: "rev-1", State: store.StateDone, Priority: 50,
		Attempts: 1, LocalAttempts: 1, LocalBackendUsed: "engine-a", Model: "model-a",
		CreatedAt: t0, StartedAt: tp(t1), FinishedAt: tp(t2), TaskDescription: "check it", ResponseBody: "an answer",
		TurnExitReason: "text_response(finish_reason=stop)",
		Usage:          store.Usage{InputTokens: ip(100), OutputTokens: ip(20), ReasoningTokens: ip(0), CacheReadTokens: ip(5), APICalls: ip(2), CostUSD: fp(0.01)},
	}
}

func finishedData(t *testing.T, j *store.Job) map[string]any {
	t.Helper()
	b, err := json.Marshal(JobFinishedEvent(events.DefaultSource, "hnx/", j, t2.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	assertFits(t, env, "agent.job.finished")
	return env["data"].(map[string]any)
}

// A completed run's record carries its final usage, sizes, timing, model and the run's tag.
func TestJobFinished_CompletedCarriesFinalUsageAndSizes(t *testing.T) {
	d := finishedData(t, doneJob())
	want := map[string]any{"run_id": "0123abcd", "profile": "profile:watcher", "profile_revision": "rev-1", "lane": "real",
		"outcome": "completed", "failure_class": nil, "backend": "engine-a", "model": "model-a", "input_bytes": 8.0,
		"output_bytes": 9.0, "turn_exit_reason": "text_response", "gateway_tag": "hnx/0123abcd", "queue_wait_s": 30.0, "wall_s": 90.0}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("%s = %v, want %v", k, d[k], v)
		}
	}
	u := d["usage"].(map[string]any)
	if u["input_tokens"] != 100.0 || u["reasoning_tokens"] != 0.0 || u["cost_usd"] != 0.01 {
		t.Errorf("usage = %v", u)
	}
}

// Unknown is null, never 0: no usage report, no start, no answer.
func TestJobFinished_NullIsUnknownNeverZero(t *testing.T) {
	j := doneJob()
	j.State, j.StartedAt, j.Usage, j.ResponseBody, j.Model, j.LocalBackendUsed, j.ProfileRevision = store.StateCancelled, nil, store.Usage{}, "", "", "", ""
	d := finishedData(t, j)
	for _, k := range []string{"usage", "started_at", "wall_s", "queue_wait_s", "output_bytes", "model", "backend", "profile_revision"} {
		if v, ok := d[k]; !ok || v != nil {
			t.Errorf("%s = %v (present %v), want null", k, v, ok)
		}
	}
}

func TestJobFinished_Outcomes(t *testing.T) {
	for _, c := range []struct {
		state   store.State
		class   string
		outcome string
	}{
		{store.StateDone, "", OutcomeCompleted},
		{store.StateCancelled, "", OutcomeCancelled},
		{store.StateBudgetKilled, "", OutcomeFailed},
		{store.StateFailed, store.FailureDeadline, OutcomeTimeout},
		{store.StateFailed, store.FailureTimeout, OutcomeTimeout},
		{store.StateFailed, store.FailureBudget, OutcomeTimeout},
		{store.StateFailed, store.FailureStall, OutcomeFailed},
		{store.StateFailed, "", OutcomeFailed},
	} {
		j := doneJob()
		j.State, j.FailureClass = c.state, c.class
		d := finishedData(t, j)
		if d["outcome"] != c.outcome {
			t.Errorf("%s/%s: outcome %v, want %s", c.state, c.class, d["outcome"], c.outcome)
		}
		if (c.outcome == OutcomeCompleted) != (d["failure_class"] == nil) {
			t.Errorf("%s/%s: failure_class %v", c.state, c.class, d["failure_class"])
		}
	}
	if _, ok := JobOutcome(&store.Job{State: store.StateRunning}); ok {
		t.Error("a running row has an outcome")
	}
}

// The lane, a retry's lineage and the tag the run's sessions carried.
func TestJobFinished_LaneSizesModelTagAndRetry(t *testing.T) {
	j := doneJob()
	j.Shadow, j.RetryOfRunID, j.RetriedByRunID, j.State, j.FailureClass = true, "parent-1", "child-1", store.StateFailed, store.FailureCapacity
	d := finishedData(t, j)
	if d["lane"] != "shadow" || d["retry_of_run_id"] != "parent-1" || d["auto_retry_scheduled"] != true || d["failure_class"] != "capacity" {
		t.Fatalf("data = %v", d)
	}
	if d["gateway_tag"] != JobGatewayTag("hnx/", j.RunID) {
		t.Errorf("gateway_tag = %v", d["gateway_tag"])
	}
}

// No text field rides along: not the task, not the answer, not a failure's text.
func TestJobFinished_NoTextLeaks(t *testing.T) {
	j := doneJob()
	j.TaskDescription, j.ResponseBody, j.LocalFailedReason = "SECRET-TASK", "SECRET-ANSWER", "SECRET-REASON"
	j.TurnExitReason = "local_processing_error(SECRET-ERROR token=abc)"
	b, _ := json.Marshal(JobFinishedEvent(events.DefaultSource, "", j, t2))
	for _, s := range []string{"SECRET", "token=abc"} {
		if strings.Contains(string(b), s) {
			t.Errorf("the record carries %q: %s", s, b)
		}
	}
}

// Values the controller does not control are sent as the schema allows or as null, never as
// something the schema refuses.
func TestJobFinished_HostileInputsFitTheSchema(t *testing.T) {
	long := strings.Repeat("m", 513)
	cases := map[string]struct {
		mod  func(*store.Job)
		key  string
		want any
	}{
		"exit text_response":      {func(j *store.Job) { j.TurnExitReason = "text_response(finish_reason=stop)" }, "turn_exit_reason", "text_response"},
		"exit max iterations":     {func(j *store.Job) { j.TurnExitReason = "max_iterations_reached(90/90)" }, "turn_exit_reason", "max_iterations_reached"},
		"exit error text dropped": {func(j *store.Job) { j.TurnExitReason = "local_processing_error(connection refused, token=abc)" }, "turn_exit_reason", "local_processing_error"},
		"exit garbage":            {func(j *store.Job) { j.TurnExitReason = "(no token) at all" }, "turn_exit_reason", nil},
		"exit too long":           {func(j *store.Job) { j.TurnExitReason = strings.Repeat("x", 65) }, "turn_exit_reason", nil},
		"underscore agent key":    {func(j *store.Job) { j.AgentKey = "file_watcher" }, "profile", ProfileUnregistered},
		"colon agent key":         {func(j *store.Job) { j.AgentKey = "a:b" }, "profile", ProfileUnregistered},
		"empty agent key":         {func(j *store.Job) { j.AgentKey = "" }, "profile", ProfileUnregistered},
		"slug over 128":           {func(j *store.Job) { j.AgentKey = strings.Repeat("a", 121) }, "profile", ProfileUnregistered},
		"slug at 128":             {func(j *store.Job) { j.AgentKey = strings.Repeat("a", 120) }, "profile", "profile:" + strings.Repeat("a", 120)},
		"model control chars":     {func(j *store.Job) { j.Model = "model\n4\a" }, "model", nil},
		"model DEL":               {func(j *store.Job) { j.Model = "model\x7f" }, "model", nil},
		"model too long":          {func(j *store.Job) { j.Model = long }, "model", nil},
		"model non-ASCII":         {func(j *store.Job) { j.Model = "modèle" }, "model", nil},
		"model invalid UTF-8":     {func(j *store.Job) { j.Model = "m\xffodel" }, "model", nil},
		"model path kept":         {func(j *store.Job) { j.Model = "/models/model-a-32b" }, "model", "/models/model-a-32b"},
		"model drive path kept":   {func(j *store.Job) { j.Model = "C:/models/a" }, "model", "C:/models/a"},
		"model URL":               {func(j *store.Job) { j.Model = "http://example.internal/m" }, "model", nil},
		"model IPv4":              {func(j *store.Job) { j.Model = strings.Join([]string{"203", "0", "113", "9"}, ".") + "/m" }, "model", nil},
		"model host:port/":        {func(j *store.Job) { j.Model = "engine:8000/m" }, "model", nil},
		"model mail address":      {func(j *store.Job) { j.Model = "a@example.internal" }, "model", nil},
		"model starting dots":     {func(j *store.Job) { j.Model = "../m" }, "model", nil},
		"backend with colon":      {func(j *store.Job) { j.LocalBackendUsed = "engine:8000" }, "backend", nil},
		"revision with space":     {func(j *store.Job) { j.ProfileRevision = "rev 1" }, "profile_revision", nil},
		"retry of with slash":     {func(j *store.Job) { j.RetryOfRunID = "a/b" }, "retry_of_run_id", nil},
		"unknown class":           {func(j *store.Job) { j.State, j.FailureClass = store.StateFailed, "Not A Class" }, "failure_class", store.FailureUnknown},
		"local attempts bounded":  {func(j *store.Job) { j.LocalAttempts = 5000 }, "local_attempts", 1000.0},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			j := doneJob()
			c.mod(j)
			if d := finishedData(t, j); d[c.key] != c.want {
				t.Errorf("%s = %v, want %v", c.key, d[c.key], c.want)
			}
		})
	}
	j := doneJob()
	j.Usage = store.Usage{InputTokens: ip(-5), ReasoningTokens: ip(0), CostUSD: fp(math.NaN())}
	u := finishedData(t, j)["usage"].(map[string]any)
	if u["input_tokens"] != nil || u["cost_usd"] != nil || u["reasoning_tokens"] != 0.0 {
		t.Errorf("usage = %v: a negative or NaN must be null, a real 0 stays 0", u)
	}
}

// The started and failed events fit their schemas, and failed carries the class and lineage.
func TestJobEvents_StartedAndFailedFitTheSchema(t *testing.T) {
	j := doneJob()
	assertFits(t, JobEvent(events.DefaultSource, EventJobStarted, j, t1))
	j.State, j.FailureClass, j.RetryOfRunID, j.Resubmits = store.StateFailed, store.FailureStall, "parent-1", 1
	e := JobEvent(events.DefaultSource, EventJobFailed, j, t2)
	assertFits(t, e, "agent.job.failed")
	d := e.Data.(JobEventData)
	if d.Reason != "stall" || d.State != "failed" || d.RetryOfRunID != "parent-1" || d.Resubmits != 1 || *d.RunSeconds != 90 {
		t.Fatalf("failed data = %+v", d)
	}
}

func TestJobEvent_ProfileRevisionDrift(t *testing.T) {
	j := doneJob()
	j.State, j.RetryOfRunID, j.ParentProfileRevision, j.ProfileRevision = store.StateFailed, "p", "rev-1", "rev-2"
	if d := JobEvent(events.DefaultSource, EventJobFailed, j, t2).Data.(JobEventData); !d.ProfileRevisionDrift {
		t.Fatal("drift not reported")
	}
	j.ProfileRevision = "rev-1"
	if d := JobEvent(events.DefaultSource, EventJobFailed, j, t2).Data.(JobEventData); d.ProfileRevisionDrift {
		t.Fatal("drift reported for one revision")
	}
}

func TestTerminalEventTypes(t *testing.T) {
	for s, want := range map[store.State]string{
		store.StateDone: EventJobFinished, store.StateCancelled: EventJobFinished,
		store.StateFailed: EventJobFailed + "," + EventJobFinished, store.StateBudgetKilled: EventJobFailed + "," + EventJobFinished,
	} {
		got, ok := TerminalEventTypes(s)
		if !ok || strings.Join(got, ",") != want {
			t.Errorf("%s = %v %v", s, got, ok)
		}
	}
	for _, s := range []store.State{store.StateQueued, store.StateAdmitted, store.StateRunning, store.StateAwaitingInference} {
		if _, ok := TerminalEventTypes(s); ok {
			t.Errorf("%s is not terminal", s)
		}
	}
}

// A job run through the scheduler publishes started then finished in the transactions of its
// transitions, each fitting its schema, the finished record naming the tag its session carried.
func TestOutbox_StartedThenFinishedWithTheSessionsTag(t *testing.T) {
	run := runnertest.New(runnertest.Answer("done"))
	r := newRig(t, rigOptions{runner: run, outbox: true})
	r.submit("run-1", defaultProfile)
	r.tick()
	evs := outboxEvents(t, r.st, "run-1")
	if len(evs) != 2 {
		t.Fatalf("events = %v", evs)
	}
	assertFits(t, evs[EventJobStarted])
	assertFits(t, evs[EventJobFinished], "agent.job.finished")
	tag := evs[EventJobFinished]["data"].(map[string]any)["gateway_tag"]
	if s := run.Sessions(); tag != s[0].GatewayTag || tag != "hnx/run-1" {
		t.Fatalf("finished tag %v, session tag %q", tag, s[0].GatewayTag)
	}
}

// A failed job publishes failed (class, lineage) then finished.
func TestOutbox_FailedEventCarriesClassAndLineage(t *testing.T) {
	r := newRig(t, rigOptions{runner: runnertest.New(runnertest.Fail(runner.Stalled, "no progress")), outbox: true})
	r.submit("run-1", defaultProfile)
	r.tick()
	evs := outboxEvents(t, r.st, "run-1")
	failed, finished := evs[EventJobFailed], evs[EventJobFinished]
	if failed == nil || finished == nil {
		t.Fatalf("events = %v", evs)
	}
	assertFits(t, failed, "agent.job.failed")
	if d := failed["data"].(map[string]any); d["reason"] != "stall" || d["resubmits"] != 0.0 {
		t.Fatalf("failed data = %v", d)
	}
}

// With no outbox the store publishes nothing, and the job still runs.
func TestOutbox_NoneIsANoop(t *testing.T) {
	r := newRig(t, rigOptions{})
	r.submit("run-1", defaultProfile)
	r.tick()
	if j := r.job("run-1"); j.State != store.StateDone {
		t.Fatalf("job = %s", j.State)
	}
	if recs, _ := r.st.PendingEvents(10); len(recs) != 0 {
		t.Fatalf("events without an outbox: %d", len(recs))
	}
}

// The events of a run are in the database once its transitions commit: a crash (the store
// closed, the process gone) loses none, and a reopened store has them to send.
func TestOutbox_JobEventsSurviveACrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orch.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.EnableOutbox(OutboxEventBuilder("svc:orchestrator", ""), 0, nil)
	r := newRig(t, rigOptions{})
	cfg := r.cfg
	cfg.Store = st
	sch, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.st = st
	r.submit("run-1", defaultProfile)
	if err := sch.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	st.Close()
	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if evs := outboxEvents(t, reopened, "run-1"); evs[EventJobStarted] == nil || evs[EventJobFinished] == nil {
		t.Fatalf("after reopening: %v", evs)
	}
}

// An agent key the schema's slug refuses gets no failed event (it could not be valid), and its
// finished record names it as unregistered.
func TestOutboxEventBuilder_NonSlugAgentKey(t *testing.T) {
	j := doneJob()
	j.AgentKey, j.State, j.FailureClass = "file_watcher", store.StateFailed, store.FailureStall
	out := OutboxEventBuilder(events.DefaultSource, "")(j)
	if len(out) != 1 {
		t.Fatalf("%d events, want the finished record only", len(out))
	}
	var e map[string]any
	if err := json.Unmarshal(out[0].Body, &e); err != nil {
		t.Fatal(err)
	}
	if e["type"] != EventJobFinished || e["data"].(map[string]any)["profile"] != ProfileUnregistered {
		t.Fatalf("event = %v", e)
	}
	if out := OutboxEventBuilder(events.DefaultSource, "")(&store.Job{State: store.StateQueued}); out != nil {
		t.Fatalf("a queued row built %v", out)
	}
}

// FuzzJobFinishedFitsSchema: whatever a row holds, the finished record fits the schema.
func FuzzJobFinishedFitsSchema(f *testing.F) {
	f.Add("watcher", "rev-1", "engine-a", "model-a", "text_response(stop)", "parent-1", 3, int64(10), 0.5)
	f.Add("A B", "rev 1", "engine:1", "http://x/y", "(x)", "a/b", -1, int64(-5), math.Inf(1))
	f.Fuzz(func(t *testing.T, agent, rev, backend, model, exit, retryOf string, local int, tokens int64, costUSD float64) {
		j := doneJob()
		j.AgentKey, j.ProfileRevision, j.LocalBackendUsed, j.Model, j.TurnExitReason, j.RetryOfRunID, j.LocalAttempts =
			agent, rev, backend, model, exit, retryOf, local
		n := int(tokens)
		j.Usage = store.Usage{InputTokens: &n, CostUSD: &costUSD}
		finishedData(t, j)
	})
}

// A profile whose agent key is no event slug is warned of once, through the scheduler's log, at
// load and at every reload.
func TestSetProfiles_WarnsOnceOfANonSlugAgentKey(t *testing.T) {
	r := newRig(t, rigOptions{profiles: map[string]string{"file_watcher": "", "watcher": ""}})
	r.sch.SetProfiles(loadProfiles(t, map[string]string{"file_watcher": "", "watcher": ""}))
	n := 0
	for _, l := range r.log.all() {
		if strings.Contains(l, `"file_watcher" is no event slug`) {
			n++
		}
		if strings.Contains(l, `"watcher"`) {
			t.Errorf("a slug key was warned of: %s", l)
		}
	}
	if n != 1 {
		t.Fatalf("warned %d times, want once", n)
	}
}
