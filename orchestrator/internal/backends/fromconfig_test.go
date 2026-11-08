// SPDX-License-Identifier: Apache-2.0

package backends

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/config"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner/runnertest"
)

func off() *bool { b := false; return &b }

// The local backends in configured order, each with a home; the interlock as each backend's own key
// says (unset is on); the cloud backend's home only.
func TestFromConfig(t *testing.T) {
	local, cloud := FromConfig(config.Backends{
		Local:         config.Backend{Name: "engine-a", Home: "/homes/a", Endpoint: "engine-a.example.internal:8000", Weight: 2, Tags: []string{"general"}, MaxContext: 131072, MaxConcurrent: 4, LoadProbeURLs: []string{"u1"}, HealthURL: "h1", NeedsInterlock: off()},
		LocalFallback: config.Backend{Name: "engine-b", Home: "/homes/b"},
		Cloud:         config.Backend{Name: "cloud", Home: "/homes/cloud", Endpoint: "cloud.example.internal:443", HealthURL: "hc", LoadProbeURLs: []string{"uc"}},
		Additional: []config.Backend{
			{Name: "no-home"},
			{Name: "engine-c", Home: "/homes/c", NeedsInterlock: off()},
		},
	})
	want := []Backend{
		{Name: "engine-a", Home: "/homes/a", NeedsInterlock: false, Weight: 2, Tags: []string{"general"}, MaxContext: 131072, MaxConcurrent: 4, LoadProbeURLs: []string{"u1"}, HealthURL: "h1", Endpoint: "engine-a.example.internal:8000"},
		{Name: "engine-b", Home: "/homes/b", NeedsInterlock: true},
		{Name: "engine-c", Home: "/homes/c", NeedsInterlock: false},
	}
	if !reflect.DeepEqual(local, want) || cloud != "/homes/cloud" {
		t.Fatalf("local = %+v\ncloud = %q", local, cloud)
	}
}

// A parsed configuration: a backend that says needs_interlock: false (what config.Migrate writes
// for the private controller's local backend, TestMigrate_KeepsTheLocalBackendsInterlockOff) is off
// the interlock; one that says nothing is on it.
func TestFromConfig_TheInterlockIsEachBackendsOwnKey(t *testing.T) {
	cfg, err := config.Parse([]byte(`db_path: /var/lib/orchestrator/controller.db
profiles_dir: /etc/orchestrator/profiles
lessons_disabled: true
backends:
  local: {name: engine-a, home: /homes/a, needs_interlock: false}
  local_fallback: {name: engine-b, home: /homes/b}
scope:
  denied_roots: [owner]
  findings_root: notes/findings/
  shared_write: [inbox/]
  reserved_names: []
`))
	if err != nil {
		t.Fatal(err)
	}
	local, _ := FromConfig(cfg.Backends)
	if len(local) != 2 || local[0].NeedsInterlock || !local[1].NeedsInterlock {
		t.Fatalf("local = %+v", local)
	}
}

// The cloud leg never carries the cloud backend's endpoint or probes, whatever the configuration
// names: progress liveness does not watch it.
func TestTheCloudLegIsNeverWatchedByItsEndpoint(t *testing.T) {
	local, cloud := FromConfig(config.Backends{
		Local: config.Backend{Name: "engine-a", Home: "/homes/a"},
		Cloud: config.Backend{Name: "cloud", Home: "/homes/cloud", Endpoint: "cloud.example.internal:443", LoadProbeURLs: []string{"uc"}},
	})
	r := runnertest.New(runnertest.On(map[string]runnertest.Step{"cloud": runnertest.Answer("cloud answer")}, runnertest.Fail(runner.BackendFault, "down")))
	p, _ := newPool(r, local...)
	p.CloudHome = cloud
	p.Limits = runner.Limits{Liveness: "progress"}
	if _, err := p.Call(context.Background(), session("run-1"), CloudFallback, noAffinity, ""); err != nil {
		t.Fatal(err)
	}
	cs := r.Sessions()[1]
	if !cs.Target.Cloud || cs.Target.Endpoint != "" || cs.Target.ProbeURLs != nil || cs.Target.Home != "/homes/cloud" {
		t.Errorf("cloud target = %+v", cs.Target)
	}
}

func TestLimitsAndJobLimitFromConfig(t *testing.T) {
	r := config.Runner{TimeoutSeconds: 60, StallTimeoutSeconds: 30, MaxTurns: 40, Liveness: "progress"}
	if got := LimitsFromConfig(r); got != (runner.Limits{Timeout: time.Minute, StallTimeout: 30 * time.Second, MaxTurns: 40, Liveness: "progress"}) {
		t.Errorf("limits = %+v", got)
	}
	for _, c := range []struct {
		job, attempt int
		want         time.Duration
	}{{90, 60, 90 * time.Second}, {0, 60, 2 * time.Minute}, {0, 0, 0}} {
		if got := JobLimitFromConfig(config.Runner{JobTimeoutSeconds: c.job, TimeoutSeconds: c.attempt}); got != c.want {
			t.Errorf("job %d, attempt %d: %v, want %v", c.job, c.attempt, got, c.want)
		}
	}
}

func TestValidate(t *testing.T) {
	good := func() *Policy {
		p, _ := newPool(nil, Backend{Name: "a", Weight: 1000, LoadProbeURLs: []string{"http://engine-a.example.internal:8000/metrics"}, HealthURL: "https://engine-a.example.internal/health"}, Backend{Name: "b"})
		p.LoadMetrics = testLoadMetrics
		return p
	}
	if err := good().Validate(); err != nil {
		t.Fatalf("a good pool: %v", err)
	}
	for name, spoil := range map[string]func(*Policy){
		"no runner":                         func(p *Policy) { p.Runner = nil },
		"a backend without a name":          func(p *Policy) { p.Backends[1].Name = "" },
		"two backends of one name":          func(p *Policy) { p.Backends[1].Name = "a" },
		"load probes with no metric to sum": func(p *Policy) { p.LoadMetrics = nil },
		"token admission without the KV pool's metrics": func(p *Policy) {
			p.TokenWeightedAdmission, p.KV = true, KVMetrics{Info: "engine:cache_info", BlocksLabel: "num_blocks"}
		},
		"a budget fraction past 1": func(p *Policy) { p.KVBudgetFraction = 1.5 },
		"a probe URL with userinfo": func(p *Policy) {
			p.Backends[0].LoadProbeURLs = []string{"http://user:pw@engine-a.example.internal:8000/metrics"}
		},
		"a probe URL that is not http": func(p *Policy) { p.Backends[0].LoadProbeURLs = []string{"file:///etc/passwd"} },
		"a probe URL without a host":   func(p *Policy) { p.Backends[0].LoadProbeURLs = []string{"http:///metrics"} },
		"a relative probe URL":         func(p *Policy) { p.Backends[0].LoadProbeURLs = []string{"u"} },
		"a health URL with userinfo":   func(p *Policy) { p.Backends[1].HealthURL = "https://user@engine-b.example.internal/health" },
		"a weight past the bound":      func(p *Policy) { p.Backends[0].Weight = maxWeight + 1 },
		"a negative weight":            func(p *Policy) { p.Backends[1].Weight = -1 },
		"an unknown liveness":          func(p *Policy) { p.Limits.Liveness = "vibes" },
	} {
		p := good()
		spoil(p)
		err := p.Validate()
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		} else if strings.Contains(err.Error(), "pw@") || strings.Contains(err.Error(), "user@") {
			t.Errorf("%s: the refusal quotes the URL's userinfo: %v", name, err)
		}
	}
	p := good()
	p.TokenWeightedAdmission, p.KV = true, KVMetrics{Info: "engine:cache_info", BlocksLabel: "num_blocks", BlockSizeLabel: "block_size"}
	if err := p.Validate(); err != nil {
		t.Errorf("blocks and block size are enough: %v", err)
	}
}

// The engine's metric names come from the configuration, and a pool built from a configuration
// without them refuses its load probes.
func TestMetricsFromConfig(t *testing.T) {
	cfg := config.EngineMetrics{Load: []string{"engine:requests_running"}, KV: config.KVMetrics{Info: "engine:cache_info", PoolLabel: "pool_tokens", Usage: "engine:cache_usage"}}
	load, kv := MetricsFromConfig(cfg)
	if !reflect.DeepEqual(load, cfg.Load) || kv != (KVMetrics{Info: "engine:cache_info", PoolLabel: "pool_tokens", Usage: "engine:cache_usage"}) {
		t.Fatalf("load %v, kv %+v", load, kv)
	}
	p, _ := newPool(nil, Backend{Name: "a", LoadProbeURLs: []string{"http://engine-a.example.internal:8000/metrics"}})
	p.LoadMetrics, p.KV = MetricsFromConfig(config.EngineMetrics{})
	if err := p.Validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("no engine metrics, load probes: %v", err)
	}
}
