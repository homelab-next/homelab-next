// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestWriter_Format(t *testing.T) {
	var b bytes.Buffer
	m := NewWriter(&b)
	m.Family("x_total", "counter", "Things.\nMore \\ help.")
	m.Sample("x_total", 3)
	m.Sample("x_total", 0.5, Label{"z", "1"}, Label{"a", "q\"u\\o\nte"})
	m.Sample("x_total", math.Inf(1))
	m.Sample("x_total", math.Inf(-1))
	m.Sample("x_total", math.NaN())
	if m.Err() != nil {
		t.Fatal(m.Err())
	}
	want := "# HELP x_total Things.\\nMore \\\\ help.\n# TYPE x_total counter\n" +
		"x_total 3\n" +
		"x_total{a=\"q\\\"u\\\\o\\nte\",z=\"1\"} 0.5\n" +
		"x_total +Inf\n" +
		"x_total -Inf\n" +
		"x_total NaN\n"
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

type failWriter struct{ n int }

func (f *failWriter) Write(p []byte) (int, error) {
	f.n++
	return 0, errShort
}

var errShort = errors.New("short write")

// The first error sticks and later calls write nothing.
func TestWriter_FirstErrorSticks(t *testing.T) {
	f := &failWriter{}
	m := NewWriter(f)
	m.Family("x", "gauge", "h")
	m.Sample("x", 1)
	if m.Err() != errShort || f.n != 1 {
		t.Fatalf("err %v after %d writes, want the first error after one write", m.Err(), f.n)
	}
}

// The prefix is a valid metric name start, names no product, and Name joins it to a suffix.
func TestPrefixIsNeutralAndValid(t *testing.T) {
	if !ValidName(Name("jobs")) || !strings.HasSuffix(Prefix, "_") {
		t.Fatalf("Prefix %q does not make valid metric names", Prefix)
	}
	if Name("jobs") != "hnx_orchestrator_jobs" {
		t.Fatalf("Name(jobs) = %q", Name("jobs"))
	}
	for _, bad := range []string{"", "1x", "a-b", "a b", "a{b}"} {
		if ValidName(bad) {
			t.Errorf("ValidName(%q) = true", bad)
		}
	}
}
