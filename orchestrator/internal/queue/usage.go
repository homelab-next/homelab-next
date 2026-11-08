// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"

	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// A runner's usage report is a JSON object (runner.Result.Usage, and one file per session under
// the usage directory). The keys read here: input_tokens, output_tokens, reasoning_tokens,
// api_calls and cache_read_tokens (counters), estimated_cost_usd or cost_usd, completed and
// failed (booleans), turn_exit_reason, session_id and model (strings), auxiliary.by_task (kept as
// raw JSON), last_prompt_tokens, max_prompt_tokens and max_tokens (per-call sizing), and
// cache_read_reported. A missing key, a null and a value of the wrong type are unknown, never 0
// or false: a report that lacks a field says nothing about it.

// maxUsageCount bounds a counter to what a float64 holds exactly.
const maxUsageCount = 1 << 53

// maxUsageFileBytes bounds one usage file read.
const maxUsageFileBytes = 1 << 20

// usageCount is a usable counter: a number from 0 to maxUsageCount.
func usageCount(usage map[string]any, key string) (float64, bool) {
	f, ok := usage[key].(float64)
	if !ok || f < 0 || f > maxUsageCount || math.IsNaN(f) {
		return 0, false
	}
	return f, true
}

func usageInt(usage map[string]any, key string) *int {
	f, ok := usageCount(usage, key)
	if !ok {
		return nil
	}
	n := int(f)
	return &n
}

// usageCost is the report's cost (estimated_cost_usd, else cost_usd), when it is a finite,
// non-negative number.
func usageCost(usage map[string]any) (float64, bool) {
	for _, k := range []string{"estimated_cost_usd", "cost_usd"} {
		if v, ok := usage[k].(float64); ok {
			if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
				return 0, false
			}
			return v, true
		}
	}
	return 0, false
}

func usageTokenCounts(usage map[string]any) store.TokenCounts {
	return store.TokenCounts{
		InputTokens:     usageInt(usage, "input_tokens"),
		OutputTokens:    usageInt(usage, "output_tokens"),
		ReasoningTokens: usageInt(usage, "reasoning_tokens"),
		APICalls:        usageInt(usage, "api_calls"),
	}
}

// summedUsageKey marks a report sumRunUsage built (a runner never writes it), whose cache-read
// count was judged per session already.
const summedUsageKey = "_hnx_summed_sessions"

// cacheReadZeroUntrusted reports whether a report's cache_read_tokens of 0 says nothing: the
// session sent real prompt tokens and the report does not state that its engine counts cache
// hits (cache_read_reported: true). An engine that counts none reports 0 for every call, which
// would read as "no cache hits" for a run whose prefix cache served most of its prompt.
func cacheReadZeroUntrusted(usage map[string]any) bool {
	in, _ := usage["input_tokens"].(float64)
	if in <= 0 {
		return false
	}
	reported, _ := usage["cache_read_reported"].(bool)
	return !reported
}

// usageFields is the report beyond the four token counters; ok is false for no report, so the
// columns stay NULL (unknown) rather than zero.
func usageFields(usage map[string]any) (store.UsageFields, bool) {
	var u store.UsageFields
	if len(usage) == 0 {
		return u, false
	}
	if b, ok := usage["completed"].(bool); ok {
		u.Completed = &b
	}
	if b, ok := usage["failed"].(bool); ok {
		u.Failed = &b
	}
	if v, ok := usage["turn_exit_reason"].(string); ok {
		u.TurnExitReason = v
	}
	if v, ok := usageCost(usage); ok {
		u.CostUSD = &v
	}
	u.CacheReadTokens = usageInt(usage, "cache_read_tokens")
	if _, summed := usage[summedUsageKey]; !summed && u.CacheReadTokens != nil && *u.CacheReadTokens == 0 && cacheReadZeroUntrusted(usage) {
		u.CacheReadUnknown = true
	}
	if v, ok := usage["session_id"].(string); ok {
		u.SessionID = v
	}
	if v, ok := usage["model"].(string); ok {
		u.Model = v
	}
	if aux, ok := usage["auxiliary"].(map[string]any); ok && aux["by_task"] != nil {
		if raw, err := json.Marshal(aux["by_task"]); err == nil {
			u.AuxByTaskJSON = string(raw)
		}
	}
	return u, true
}

// usageCallSizing is the report's per-call sizing; a missing, zero or wrong-typed key is unknown.
func usageCallSizing(usage map[string]any) (store.CallSizing, bool) {
	pos := func(key string) *int {
		f, ok := usageCount(usage, key)
		if !ok || f <= 0 {
			return nil
		}
		n := int(f)
		return &n
	}
	c := store.CallSizing{
		LastCallPromptTokens: pos("last_prompt_tokens"),
		MaxCallPromptTokens:  pos("max_prompt_tokens"),
		MaxTokensRequested:   pos("max_tokens"),
	}
	return c, c.LastCallPromptTokens != nil || c.MaxCallPromptTokens != nil || c.MaxTokensRequested != nil
}

// additiveCounters sum across a run's sessions; the cost sums too, as one counter.
var additiveCounters = []string{"input_tokens", "output_tokens", "reasoning_tokens", "api_calls", "cache_read_tokens"}

// sumRunUsage is last (the final session's report: completed, session_id, turn_exit_reason, ...)
// with every additive counter replaced by its sum over runID's usage files in dir (<run id>.json
// and <run id>.*.json: every attempt and every leg). Unknown is per session: a counter one session
// left unknown (or a cache-read zero that session's report cannot vouch for) makes the run's total
// unknown, never a smaller known number. ok is false when no file was read. The run id is one the
// gateway tag accepted (no path separator, no pattern character).
func sumRunUsage(dir, runID string, last map[string]any) (map[string]any, bool) {
	paths := []string{filepath.Join(dir, runID+".json")}
	more, _ := filepath.Glob(filepath.Join(dir, runID+".*.json"))
	paths = append(paths, more...)
	sums := map[string]float64{}
	unknown := map[string]bool{}
	var cost float64
	costUnknown, found := false, false
	for _, p := range paths {
		u, ok := readUsageFile(p)
		if !ok {
			continue
		}
		found = true
		for _, k := range additiveCounters {
			v, ok := usageCount(u, k)
			if !ok || (k == "cache_read_tokens" && v == 0 && cacheReadZeroUntrusted(u)) {
				unknown[k] = true
				continue
			}
			sums[k] += v
		}
		if v, ok := usageCost(u); ok {
			cost += v
		} else {
			costUnknown = true
		}
	}
	if !found {
		return last, false
	}
	out := make(map[string]any, len(last)+len(additiveCounters)+3)
	for k, v := range last {
		out[k] = v
	}
	for _, k := range additiveCounters {
		if unknown[k] {
			out[k] = nil
		} else {
			out[k] = sums[k]
		}
	}
	if costUnknown {
		out["estimated_cost_usd"], out["cost_usd"] = nil, nil
	} else {
		out["estimated_cost_usd"], out["cost_usd"] = cost, cost
	}
	out[summedUsageKey] = true
	return out, true
}

// readUsageFile reads one usage report: a regular file of at most maxUsageFileBytes holding a
// JSON object. Anything else is no report.
func readUsageFile(path string) (map[string]any, bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxUsageFileBytes {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var u map[string]any
	if json.Unmarshal(data, &u) != nil || u == nil {
		return nil, false
	}
	return u, true
}
