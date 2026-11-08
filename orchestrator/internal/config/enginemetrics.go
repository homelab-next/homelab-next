// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"

	"go.yaml.in/yaml/v3"

	"github.com/homelab-next/homelab-next/orchestrator/internal/grants"
)

// EngineMetrics names the metrics a backend's load_probe_urls serve: the gauges summed into its
// load (its running and waiting requests) and, for token-weighted admission, its KV pool's. They
// are the inference engine's own names, so no default is built in and this repository spells none:
// a site writes them, from its own file (LoadEngineMetrics) or by hand, and the provider module of
// the engine is their long-term home (its manifest, once engines are modules). Without them the
// pool refuses load probes it could not read (backends.Policy.Validate).
type EngineMetrics struct {
	// Load are the gauges summed into a backend's load.
	Load []string `yaml:"load,omitempty"`
	// KV are the KV pool's metrics.
	KV KVMetrics `yaml:"kv,omitempty"`
}

// KVMetrics names a KV pool's metrics: Info, an info metric whose PoolLabel (else BlocksLabel
// times BlockSizeLabel) holds the pool in tokens, and Usage, a gauge of the fraction in use.
type KVMetrics struct {
	Info           string `yaml:"info,omitempty"`
	PoolLabel      string `yaml:"pool_label,omitempty"`
	BlocksLabel    string `yaml:"blocks_label,omitempty"`
	BlockSizeLabel string `yaml:"block_size_label,omitempty"`
	Usage          string `yaml:"usage,omitempty"`
}

// IsZero reports whether m names nothing.
func (m EngineMetrics) IsZero() bool { return len(m.Load) == 0 && m.KV == (KVMetrics{}) }

var (
	metricNameRe = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]{0,199}$`)
	labelNameRe  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,99}$`)
)

// Check holds every name to the metrics format's own rules (a metric name, a label name).
func (m EngineMetrics) Check() error {
	for _, n := range m.Load {
		if !metricNameRe.MatchString(n) {
			return fmt.Errorf("engine_metrics.load: %q is not a metric name", n)
		}
	}
	for _, f := range []struct {
		key, v string
		re     *regexp.Regexp
	}{
		{"info", m.KV.Info, metricNameRe}, {"usage", m.KV.Usage, metricNameRe},
		{"pool_label", m.KV.PoolLabel, labelNameRe}, {"blocks_label", m.KV.BlocksLabel, labelNameRe},
		{"block_size_label", m.KV.BlockSizeLabel, labelNameRe},
	} {
		if f.v != "" && !f.re.MatchString(f.v) {
			return fmt.Errorf("engine_metrics.kv.%s: %q is not a valid name", f.key, f.v)
		}
	}
	return nil
}

// maxEngineMetricsBytes bounds a site's engine metrics file.
const maxEngineMetricsBytes = 64 << 10

// LoadEngineMetrics reads a site's engine metrics file: a regular file (not a link, not a FIFO) of
// at most 64 KiB holding one YAML document, one mapping with the keys of EngineMetrics (load, kv),
// decoded strictly and checked.
func LoadEngineMetrics(path string) (EngineMetrics, error) {
	// a regular file, opened without following a link or blocking (a FIFO), at most 64 KiB
	data, err := grants.ReadConfigFile(path, maxEngineMetricsBytes)
	if err != nil {
		return EngineMetrics{}, fmt.Errorf("read engine metrics: %w", err)
	}
	var m EngineMetrics
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		if errors.Is(err, io.EOF) {
			return EngineMetrics{}, fmt.Errorf("engine metrics %s: the file is empty", path)
		}
		return EngineMetrics{}, fmt.Errorf("engine metrics %s: %w", path, err)
	}
	var more yaml.Node
	if err := dec.Decode(&more); !errors.Is(err, io.EOF) {
		return EngineMetrics{}, fmt.Errorf("engine metrics %s: one YAML document only", path)
	}
	if m.IsZero() {
		return EngineMetrics{}, fmt.Errorf("engine metrics %s: names no metric", path)
	}
	if err := m.Check(); err != nil {
		return EngineMetrics{}, fmt.Errorf("engine metrics %s: %w", path, err)
	}
	return m, nil
}

// anyLoadProbes reports whether any backend of the configuration document has load probes.
func anyLoadProbes(root *yaml.Node) bool {
	b := lookup(root, "backends")
	if b == nil || b.Kind != yaml.MappingNode {
		return false
	}
	has := func(n *yaml.Node) bool {
		if n == nil || n.Kind != yaml.MappingNode {
			return false
		}
		p := lookup(n, "load_probe_urls")
		return p != nil && p.Kind == yaml.SequenceNode && len(p.Content) > 0
	}
	for _, k := range []string{"local", "local_fallback", "cloud"} {
		if has(lookup(b, k)) {
			return true
		}
	}
	if add := lookup(b, "additional"); add != nil && add.Kind == yaml.SequenceNode {
		for _, n := range add.Content {
			if has(n) {
				return true
			}
		}
	}
	return false
}
