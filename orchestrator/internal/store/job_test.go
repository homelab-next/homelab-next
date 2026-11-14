// SPDX-License-Identifier: Apache-2.0

package store

import "testing"

func TestCanTransition(t *testing.T) {
	cases := []struct {
		from, to State
		want     bool
	}{
		{StateQueued, StateAdmitted, true},
		{StateQueued, StateCancelled, true},
		{StateAdmitted, StateRunning, true},
		{StateAdmitted, StateQueued, true}, // an admission that lost its race goes back
		{StateRunning, StateAwaitingInference, true},
		{StateRunning, StateDone, true},
		{StateRunning, StateFailed, true},
		{StateRunning, StateBudgetKilled, true},
		{StateRunning, StateCancelled, true},
		{StateRunning, StateQueued, true}, // a retry whose backend was drained meanwhile
		{StateAwaitingInference, StateRunning, true},
		{StateAwaitingInference, StateFailed, true},

		{StateDone, StateRunning, false}, // terminal states go nowhere
		{StateFailed, StateQueued, false},
		{StateCancelled, StateAdmitted, false},
		{StateBudgetKilled, StateQueued, false},
		{StateQueued, StateRunning, false}, // no skipping admission
		{StateAwaitingInference, StateDone, false},
	}
	for _, c := range cases {
		if got := CanTransition(c.from, c.to); got != c.want {
			t.Errorf("CanTransition(%s, %s) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

func TestValidState(t *testing.T) {
	for _, s := range AllStates {
		if !ValidState(s) {
			t.Errorf("ValidState(%s) = false", s)
		}
	}
	for _, s := range []State{"finished", "", "Queued"} {
		if ValidState(s) {
			t.Errorf("ValidState(%q) = true", s)
		}
	}
}
