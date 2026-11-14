// SPDX-License-Identifier: Apache-2.0

// Package metrics writes the Prometheus text exposition format (version 0.0.4) with the standard
// library only. The controller's metrics are a handful of gauges and counters computed on each
// scrape, which needs no client library.
//
// Every metric the controller exposes is named Prefix + a suffix ([Name]). The prefix names no
// product: the controller was once deployed with another prefix, and the move to this one is a
// cutover concern (docs/orchestration-controller.md, "Neutral names").
package metrics

import (
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ContentType is the exposition format's media type.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Prefix starts the name of every metric the controller exposes.
const Prefix = "hnx_orchestrator_"

// Name returns the full metric name for suffix (Prefix + suffix).
func Name(suffix string) string { return Prefix + suffix }

// metricName is the exposition format's rule for a metric name.
var metricName = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

// ValidName reports whether name is a valid metric name in the exposition format.
func ValidName(name string) bool { return metricName.MatchString(name) }

// Label is one name="value" pair.
type Label struct{ Name, Value string }

// Writer emits metric families to an io.Writer. The first write error sticks and is returned by
// Err; later calls do nothing.
type Writer struct {
	w   io.Writer
	err error
}

// NewWriter returns a Writer on w.
func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// Err is the first write error, if any.
func (m *Writer) Err() error { return m.err }

func (m *Writer) printf(format string, a ...any) {
	if m.err == nil {
		_, m.err = fmt.Fprintf(m.w, format, a...)
	}
}

// Family writes the HELP and TYPE lines; typ is "gauge" or "counter".
func (m *Writer) Family(name, typ, help string) {
	m.printf("# HELP %s %s\n# TYPE %s %s\n", name, escapeHelp(help), name, typ)
}

// Sample writes one sample. Labels are written sorted by name, so the output is deterministic.
func (m *Writer) Sample(name string, v float64, labels ...Label) {
	if len(labels) == 0 {
		m.printf("%s %s\n", name, formatValue(v))
		return
	}
	sorted := append([]Label(nil), labels...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	parts := make([]string, len(sorted))
	for i, l := range sorted {
		parts[i] = l.Name + `="` + escapeLabel(l.Value) + `"`
	}
	m.printf("%s{%s} %s\n", name, strings.Join(parts, ","), formatValue(v))
}

// Bool is 1 for true and 0 for false.
func Bool(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
var helpEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`)

func escapeLabel(s string) string { return labelEscaper.Replace(s) }
func escapeHelp(s string) string  { return helpEscaper.Replace(s) }
