// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// Aging: every AgingStepS seconds a job waits lowers its effective priority by AgingStepPri, so a
// low-priority job is never starved for ever by a stream of higher-priority ones.
const (
	AgingStepPri = 5
	AgingStepS   = 900.0
)

// EffectivePriority is max(1, priority - AgingStepPri * floor(waitSeconds / AgingStepS)): a lower
// number runs first.
func EffectivePriority(priority int, waitSeconds float64) int {
	steps := int(waitSeconds / AgingStepS)
	return max(1, priority-AgingStepPri*steps)
}

// PickNext returns the candidate with the lowest effective priority at now, the earliest
// submitted (lowest seq) on a tie; nil when there is none.
func PickNext(candidates []*store.Job, now time.Time) *store.Job {
	var best *store.Job
	var bestEff int
	for _, c := range candidates {
		eff := EffectivePriority(c.Priority, now.Sub(c.CreatedAt).Seconds())
		if best == nil || eff < bestEff || (eff == bestEff && c.Seq < best.Seq) {
			best, bestEff = c, eff
		}
	}
	return best
}
