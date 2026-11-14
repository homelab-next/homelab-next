// SPDX-License-Identifier: Apache-2.0

package store

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
)

// The usage report's fields, the prompt provenance and the session id round-trip, and stay
// unknown until written; an empty session id never clears a stored one.
func TestUsageFieldsAndPromptProvenance(t *testing.T) {
	s := openTest(t)
	mkJob(t, s, "uf", "agent-a", StateQueued)
	before, _ := s.GetJob("uf")
	if before.Completed != nil || before.Failed != nil || before.PromptSHA256 != "" || before.CostUSD != 0 || before.Usage.Known() || before.Model != "" || before.SessionID != "" {
		t.Fatalf("before = %+v, want unknown", before)
	}
	tr, fl := true, false
	if err := s.UpdateUsageFields("uf", UsageFields{
		Completed: &tr, Failed: &fl, TurnExitReason: "text_response", CostUSD: floatp(0.0123),
		Model: "example-model-8b", AuxByTaskJSON: `{"compression":{"api_calls":1}}`, SessionID: "sess-9",
		CacheReadTokens: intp(4096),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdatePromptProvenance("uf", []string{"lesson-a", "lesson-b"}, []string{"runbook-a"}, "abc123", 777); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateAttempts("uf", 2); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetJob("uf")
	if got.Completed == nil || !*got.Completed || got.Failed == nil || *got.Failed {
		t.Errorf("Completed/Failed = %v/%v", got.Completed, got.Failed)
	}
	if got.TurnExitReason != "text_response" || got.CostUSD != 0.0123 || got.CacheReadTokens != 4096 || got.Attempts != 2 {
		t.Errorf("usage = %+v", got)
	}
	if got.Model != "example-model-8b" || got.Usage.CostUSD == nil || *got.Usage.CostUSD != 0.0123 ||
		got.Usage.CacheReadTokens == nil || *got.Usage.CacheReadTokens != 4096 {
		t.Errorf("model/usage = %q / %+v", got.Model, got.Usage)
	}
	if got.AuxByTask != `{"compression":{"api_calls":1}}` || got.SessionID != "sess-9" {
		t.Errorf("aux/session = %q / %q", got.AuxByTask, got.SessionID)
	}
	if got.InjectedLessons != "lesson-a,lesson-b" || got.InjectedRunbooks != "runbook-a" || got.PromptSHA256 != "abc123" || got.PromptBytes != 777 {
		t.Errorf("provenance = %+v", got)
	}
	if err := s.UpdateUsageFields("uf", UsageFields{TurnExitReason: "x"}); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.GetJob("uf"); again.SessionID != "sess-9" {
		t.Errorf("an empty session id cleared the stored one: %q", again.SessionID)
	}
}

// A cache-read count marked unknown is stored as NULL; a real one as the number.
func TestUpdateUsageFields_CacheReadUnknownStoresNull(t *testing.T) {
	s := openTest(t)
	mkJob(t, s, "c1", "agent-a", StateQueued)
	mkJob(t, s, "c2", "agent-a", StateQueued)
	if err := s.UpdateUsageFields("c1", UsageFields{CacheReadUnknown: true, CacheReadTokens: intp(5)}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUsageFields("c2", UsageFields{CacheReadTokens: intp(4096)}); err != nil {
		t.Fatal(err)
	}
	var v1, v2 sql.NullInt64
	s.db.QueryRow(`SELECT cache_read_tokens FROM jobs WHERE run_id = 'c1'`).Scan(&v1)
	s.db.QueryRow(`SELECT cache_read_tokens FROM jobs WHERE run_id = 'c2'`).Scan(&v2)
	if v1.Valid {
		t.Errorf("unknown cache read stored %d, want NULL", v1.Int64)
	}
	if !v2.Valid || v2.Int64 != 4096 {
		t.Errorf("known cache read = %+v, want 4096", v2)
	}
}

// Call sizing is unknown until written, round-trips, and a partial update keeps what it omits.
func TestCallSizing(t *testing.T) {
	s := openTest(t)
	mkJob(t, s, "j1", "agent-a", StateQueued)
	got, err := s.GetCallSizing("j1")
	if err != nil || got.LastCallPromptTokens != nil || got.MaxCallPromptTokens != nil || got.MaxTokensRequested != nil || got.WaitCause != "" {
		t.Fatalf("new job sizing = %+v, %v", got, err)
	}
	if err := s.UpdateCallSizing("j1", CallSizing{LastCallPromptTokens: intp(61000), MaxCallPromptTokens: intp(72000), WaitCause: "slot"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateCallSizing("j1", CallSizing{MaxTokensRequested: intp(16384)}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetCallSizing("j1")
	if got.LastCallPromptTokens == nil || *got.LastCallPromptTokens != 61000 || got.MaxCallPromptTokens == nil || *got.MaxCallPromptTokens != 72000 ||
		got.MaxTokensRequested == nil || *got.MaxTokensRequested != 16384 || got.WaitCause != "slot" {
		t.Fatalf("after two writes = %+v", got)
	}
	if _, err := s.GetCallSizing("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetCallSizing(missing) = %v", err)
	}
}

// The percentile is the nearest rank over the agent's done jobs that recorded a size; queued
// jobs, other agents and unrecorded sizes stay out, and no history is (0, 0).
func TestAgentLastCallPromptP90(t *testing.T) {
	s := openTest(t)
	if p, n, err := s.AgentLastCallPromptP90("nobody", 0); err != nil || p != 0 || n != 0 {
		t.Fatalf("no history = %d, %d, %v", p, n, err)
	}
	for i := 1; i <= 10; i++ {
		id := fmt.Sprintf("d%d", i)
		mkJob(t, s, id, "agent-x", StateDone)
		_ = s.UpdateCallSizing(id, CallSizing{LastCallPromptTokens: intp(i * 10000)})
	}
	mkJob(t, s, "q", "agent-x", StateQueued)
	_ = s.UpdateCallSizing("q", CallSizing{LastCallPromptTokens: intp(999999)})
	mkJob(t, s, "other", "agent-y", StateDone)
	_ = s.UpdateCallSizing("other", CallSizing{LastCallPromptTokens: intp(888888)})
	mkJob(t, s, "unrecorded", "agent-x", StateDone)
	p, n, err := s.AgentLastCallPromptP90("agent-x", 200)
	if err != nil || n != 10 || p != 90000 {
		t.Errorf("p90, n = %d, %d (%v); want 90000, 10", p, n, err)
	}
}
