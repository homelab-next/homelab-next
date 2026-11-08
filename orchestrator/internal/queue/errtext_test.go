// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"testing"

	"github.com/homelab-next/homelab-next/orchestrator/internal/errtext"
)

// The queue decides on the pool's sentinels and the runner classes only: no file of it decides on
// an error's text or a session's output, or imports regexp (package errtext).
//
// Its own sinks, each of which only bounds, logs or keeps the text: logf (the log), boundText
// (bounds the answer), failRunning (logs and stores a reason), and the store's writes that keep a
// result (UpdateExecutionResult).
var queueSinks = errtext.Options{Sinks: []string{".logf", "boundText", ".failRunning", ".UpdateExecutionResult"}}

func TestTheQueueReadsNoErrorText(t *testing.T) {
	got, err := errtext.CheckWith(".", queueSinks)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		t.Error(f)
	}
}
