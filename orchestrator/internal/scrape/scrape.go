// SPDX-License-Identifier: Apache-2.0

// Package scrape reads samples from an endpoint that serves the metrics text exposition format
// (version 0.0.4): an inference engine's own metrics, read by the backend pool for a backend's
// load and its KV pool. It is a probe: one GET, no body, no credential, no redirect followed and no
// environment proxy used, and a probe that cannot be read is "no reading", never an error a
// dispatch could fail on.
//
// The parser reads the sample lines it is asked for: a metric name, an optional label set in
// braces (quoted values, with the format's \\, \" and \n escapes), a value. Comment lines, blank
// lines and the samples of other metrics are skipped unparsed, so a line the parser does not
// understand costs the reading of that line only.
package scrape

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// MaxBodyBytes bounds what one scrape reads; a larger body is read up to here and the rest is
// ignored, so an endpoint cannot make a probe hold memory without bound.
const MaxBodyBytes = 4 << 20

// maxLineBytes bounds one line (an info metric's label set can be long).
const maxLineBytes = 256 << 10

// Sample is one sample line.
type Sample struct {
	Name   string
	Labels map[string]string // nil when the line has no label set
	Value  float64
}

// ErrStatus is wrapped by Fetch for an answer other than 200.
var ErrStatus = errors.New("scrape: the endpoint answered a status other than 200")

// NewClient returns the client a probe uses by default: no proxy from the environment (a probe
// goes to the address it names, never through a proxy that may log it) and no redirect followed (the
// reading must come from the URL configured).
func NewClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Fetch GETs url within timeout and returns the samples whose metric name want accepts (nil:
// every sample). An answer other than 200 is an error wrapping ErrStatus.
func Fetch(ctx context.Context, client *http.Client, url string, timeout time.Duration, want func(name string) bool) ([]Sample, error) {
	if client == nil {
		client = NewClient()
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w (%d)", ErrStatus, resp.StatusCode)
	}
	return Parse(io.LimitReader(resp.Body, MaxBodyBytes), want)
}

// Parse reads the sample lines of r whose metric name want accepts (nil: every one). A line that
// does not parse is skipped. The only error is the reader's own (a line past the line bound
// included).
func Parse(r io.Reader, want func(name string) bool) ([]Sample, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	var out []Sample
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		name := metricName(line)
		if name == "" || (want != nil && !want(name)) {
			continue
		}
		if s, ok := parseLine(line, name); ok {
			out = append(out, s)
		}
	}
	return out, sc.Err()
}

// metricName is the line's leading metric name: [a-zA-Z_:][a-zA-Z0-9_:]*.
func metricName(line string) string {
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '_' || c == ':' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		case c >= '0' && c <= '9' && i > 0:
		default:
			return line[:i]
		}
	}
	return line
}

// parseLine reads `name{labels} value [timestamp]`.
func parseLine(line, name string) (Sample, bool) {
	s := Sample{Name: name}
	rest := line[len(name):]
	if strings.HasPrefix(rest, "{") {
		labels, n, ok := parseLabels(rest)
		if !ok {
			return Sample{}, false
		}
		s.Labels = labels
		rest = rest[n:]
	}
	if rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
		return Sample{}, false
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 || len(fields) > 2 {
		return Sample{}, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || math.IsNaN(v) {
		return Sample{}, false
	}
	s.Value = v
	return s, true
}

// parseLabels reads a label set starting at s[0] == '{' and returns it with the bytes consumed.
func parseLabels(s string) (map[string]string, int, bool) {
	labels := map[string]string{}
	i := 1
	for {
		for i < len(s) && (s[i] == ' ' || s[i] == ',') {
			i++
		}
		if i >= len(s) {
			return nil, 0, false
		}
		if s[i] == '}' {
			return labels, i + 1, true
		}
		start := i
		for i < len(s) && s[i] != '=' && s[i] != '}' && s[i] != ',' && s[i] != ' ' {
			i++
		}
		key := s[start:i]
		if key == "" || i >= len(s) || s[i] != '=' || i+1 >= len(s) || s[i+1] != '"' {
			return nil, 0, false
		}
		i += 2
		var b strings.Builder
		closed := false
		for i < len(s) {
			c := s[i]
			if c == '\\' && i+1 < len(s) {
				switch s[i+1] {
				case 'n':
					b.WriteByte('\n')
				case '\\', '"':
					b.WriteByte(s[i+1])
				default:
					b.WriteByte('\\')
					b.WriteByte(s[i+1])
				}
				i += 2
				continue
			}
			if c == '"' {
				closed = true
				i++
				break
			}
			b.WriteByte(c)
			i++
		}
		if !closed {
			return nil, 0, false
		}
		if _, dup := labels[key]; dup {
			return nil, 0, false
		}
		labels[key] = b.String()
	}
}

// Sum adds the values of every sample of the named metrics. ok is false when none was found.
func Sum(samples []Sample, names ...string) (total float64, ok bool) {
	for _, s := range samples {
		for _, n := range names {
			if s.Name == n {
				total += s.Value
				ok = true
			}
		}
	}
	return total, ok
}

// Max is the largest value among the samples of the named metrics. ok is false when none was found.
func Max(samples []Sample, names ...string) (max float64, ok bool) {
	for _, s := range samples {
		for _, n := range names {
			if s.Name == n && (!ok || s.Value > max) {
				max, ok = s.Value, true
			}
		}
	}
	return max, ok
}

// Names returns a want func accepting exactly names.
func Names(names ...string) func(string) bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		if n != "" {
			set[n] = true
		}
	}
	return func(n string) bool { return set[n] }
}
