// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"strings"
	"testing"
)

func validConfig() map[string]any {
	return baseConfig("http://a.svc.lab.example:8000", "http://b.svc.lab.example:8000",
		"http://c.svc.lab.example", "https://api.anthropic.com")
}

func parse(t *testing.T, cfg map[string]any) error {
	t.Helper()
	_, err := ParseConfig(mustJSON(cfg))
	return err
}

func keyOf(cfg map[string]any, i int) map[string]any { return cfg["keys"].([]any)[i].(map[string]any) }

func depOf(cfg map[string]any, role string, i int) map[string]any {
	return roleOf(cfg, role)["deployments"].([]any)[i].(map[string]any)
}

func TestGatewayConfigAcceptsTheContractShape(t *testing.T) {
	if err := parse(t, validConfig()); err != nil {
		t.Fatal(err)
	}
	// the contract's own example, verbatim
	example := `{"version":"1.0","name":"lab-in-a-box","admin_key_env":"HNX_SECRET_LLM_GATEWAY_MASTER_KEY",
	"roles":{"fast-classifier":{"kind":"chat","max_context_tokens":8192,"tlp_ceiling":"red","leaves_lab":false,
	"deployments":[{"id":"fast-classifier-1","backend":"fake-inference","locality":"local","protocol":"openai",
	"base_url":"http://fake-inference.svc.lab.example:8000","model":"backend-small","api_key_env":null}],"fallbacks":[],
	"limits":{"window_s":60,"max_requests":600,"max_tokens":null,"max_cost":null},"cost_per_1k_tokens":null}},
	"keys":[{"alias":"conformance-throttle","key_env":"HNX_SECRET_LLM_GATEWAY_KEY_CONFORMANCE_THROTTLE",
	"owner":"conformance-throttle","data_tier":"local-only","tlp_ceiling":"red","roles":["fast-classifier"],
	"limits":{"window_s":60,"max_requests":3,"max_tokens":null}}],
	"telemetry_reader":{"key_env":"HNX_SECRET_LLM_GATEWAY_TELEMETRY_READER"}}`
	if _, err := ParseConfig([]byte(example)); err != nil {
		t.Fatal(err)
	}
	// R13: a cloud deployment may point anywhere (a conformance fixture points it at the fake)
	cfg := validConfig()
	depOf(cfg, "cloud", 0)["base_url"] = "http://127.0.0.1:9999"
	if err := parse(t, cfg); err != nil {
		t.Fatal(err)
	}
	// a higher minor with only known keys is accepted; conformance_only is optional
	cfg = validConfig()
	cfg["version"], cfg["conformance_only"] = "1.7", true
	c, err := ParseConfig(mustJSON(cfg))
	if err != nil || !c.ConformanceOnly {
		t.Fatal(err)
	}
}

func TestGatewayConfigRefusals(t *testing.T) {
	cases := []struct {
		name, want string
		edit       func(cfg map[string]any)
	}{
		{"unknown top-level key", "unknown field", func(c map[string]any) { c["bifrost"] = map[string]any{} }},
		{"unknown role key", "unknown field", func(c map[string]any) { roleOf(c, "chat-a")["weight"] = 1 }},
		{"unknown deployment key", "unknown field", func(c map[string]any) { depOf(c, "chat-a", 0)["rpm"] = 1 }},
		{"unknown key key", "unknown field", func(c map[string]any) { keyOf(c, 0)["models"] = []any{} }},
		{"max_cost on a key", "unknown field", func(c map[string]any) {
			keyOf(c, 1)["limits"].(map[string]any)["max_cost"] = 1
		}},
		{"missing field", `missing "fallbacks"`, func(c map[string]any) { delete(roleOf(c, "chat-b"), "fallbacks") }},
		{"missing api_key_env", `missing "api_key_env"`, func(c map[string]any) { delete(depOf(c, "chat-b", 0), "api_key_env") }},
		{"bad major", "version", func(c map[string]any) { c["version"] = "2.0" }},
		{"bad version", "version", func(c map[string]any) { c["version"] = "1" }},
		{"bad name", "not a slug", func(c map[string]any) { c["name"] = "Bad_Name" }},
		{"env not a secret name", "environment name", func(c map[string]any) { c["admin_key_env"] = "MASTER_KEY" }},
		{"no roles", "at least one role", func(c map[string]any) {
			c["roles"] = map[string]any{}
			c["keys"] = []any{}
		}},
		{"bad kind", "kind", func(c map[string]any) { roleOf(c, "chat-b")["kind"] = "completion" }},
		{"bad ceiling", "canonical TLP label", func(c map[string]any) { roleOf(c, "chat-b")["tlp_ceiling"] = "TLP:RED" }},
		{"bad key ceiling", "canonical TLP label", func(c map[string]any) { keyOf(c, 0)["tlp_ceiling"] = "white" }},
		{"no deployments", "at least one deployment", func(c map[string]any) { roleOf(c, "chat-b")["deployments"] = []any{} }},
		{"deployment id", "expected \"chat-a-2\"", func(c map[string]any) { depOf(c, "chat-a", 1)["id"] = "chat-a-3" }},
		{"bad protocol", "protocol", func(c map[string]any) { depOf(c, "chat-b", 0)["protocol"] = "gemini" }},
		{"bad locality", "locality", func(c map[string]any) { depOf(c, "chat-b", 0)["locality"] = "edge" }},
		{"base_url path", "no path", func(c map[string]any) { depOf(c, "chat-b", 0)["base_url"] = "http://x/v1" }},
		{"base_url slash", "no path", func(c map[string]any) { depOf(c, "chat-b", 0)["base_url"] = "http://x/" }},
		{"base_url scheme", "http or https", func(c map[string]any) { depOf(c, "chat-b", 0)["base_url"] = "ftp://x" }},
		{"base_url userinfo", "scheme://host", func(c map[string]any) { depOf(c, "chat-b", 0)["base_url"] = "http://u:p@x" }},
		{"embedding on anthropic", "embedding role cannot be served by an anthropic", func(c map[string]any) {
			depOf(c, "embed", 0)["protocol"] = "anthropic"
		}},
		{"cloud deployment on an in-lab role", "leaves_lab false", func(c map[string]any) { roleOf(c, "cloud")["leaves_lab"] = false }},
		{"leaves_lab role above green", "leaves the lab, so its tlp_ceiling must be green or clear", func(c map[string]any) {
			roleOf(c, "cloud")["tlp_ceiling"] = "amber"
		}},
		{"leaves_lab role at red", "tlp_ceiling must be green or clear, not red", func(c map[string]any) {
			roleOf(c, "cloud")["tlp_ceiling"] = "red"
		}},
		{"fallback to itself", "itself", func(c map[string]any) { roleOf(c, "chat-b")["fallbacks"] = []any{"chat-b"} }},
		{"fallback unknown", "is not a role", func(c map[string]any) { roleOf(c, "chat-b")["fallbacks"] = []any{"zz"} }},
		{"fallback other kind", "fallback embed is a embedding role but role chat-b is a chat role", func(c map[string]any) { roleOf(c, "chat-b")["fallbacks"] = []any{"embed"} }},
		{"max_cost without cost", "needs cost_per_1k_tokens", func(c map[string]any) {
			roleOf(c, "chat-b")["limits"] = map[string]any{"window_s": 60, "max_requests": nil, "max_tokens": nil, "max_cost": 1}
		}},
		{"window zero", "window_s", func(c map[string]any) {
			keyOf(c, 1)["limits"].(map[string]any)["window_s"] = 0
		}},
		{"duplicate alias", "declared twice", func(c map[string]any) { keyOf(c, 1)["alias"] = "agent-a" }},
		{"unsorted keys", "sorted by alias", func(c map[string]any) { c["keys"] = []any{keyOf(c, 1), keyOf(c, 0)} }},
		{"duplicate env", "already used", func(c map[string]any) { keyOf(c, 1)["key_env"] = "HNX_SECRET_AGENT" }},
		{"key env is admin env", "already used", func(c map[string]any) { keyOf(c, 1)["key_env"] = "HNX_SECRET_ADMIN" }},
		{"provider env is a caller env", "also", func(c map[string]any) { depOf(c, "cloud", 0)["api_key_env"] = "HNX_SECRET_LOCAL" }},
		{"key role not in roles", "is not in roles", func(c map[string]any) { keyOf(c, 1)["roles"] = []any{"chat-b", "zz"} }},
		{"key roles unsorted", "must be sorted", func(c map[string]any) { keyOf(c, 0)["roles"] = []any{"embed", "chat-a", "chat-b", "cloud"} }},
		{"key misses a fallback", "does not list", func(c map[string]any) { keyOf(c, 0)["roles"] = []any{"chat-a", "cloud", "embed"} }},
		{"local-only key on a leaves-lab role", "local-only key", func(c map[string]any) {
			keyOf(c, 1)["roles"] = []any{"chat-b", "cloud"}
		}},
		{"local-only key on a cloud deployment", "local-only key", func(c map[string]any) {
			roleOf(c, "chat-b")["leaves_lab"] = true
			depOf(c, "chat-b", 0)["locality"] = "cloud"
		}},
		{"bad owner", "owner", func(c map[string]any) { keyOf(c, 1)["owner"] = "someone" }},
		{"bad data tier", "data_tier", func(c map[string]any) { keyOf(c, 1)["data_tier"] = "any" }},
		{"negative limit", "negative", func(c map[string]any) {
			keyOf(c, 1)["limits"].(map[string]any)["max_requests"] = -1
		}},
		{"conformance_only not a bool", "not a gateway config", func(c map[string]any) { c["conformance_only"] = "yes" }},
	}
	for _, c := range cases {
		cfg := validConfig()
		c.edit(cfg)
		err := parse(t, cfg)
		var ce *ConfigError
		if err == nil || !errors.As(err, &ce) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if _, err := ParseConfig([]byte(`{"version":"1.0"} {}`)); err == nil {
		t.Error("trailing data accepted")
	}
}

func TestGatewayConfigKeysAreExactAndUnique(t *testing.T) {
	good := string(mustJSON(validConfig()))
	for _, c := range []struct{ name, old, new, want string }{
		{"duplicate top-level key", `"version":"1.0"`, `"version":"1.0","version":"1.0"`, `config: key "version" appears twice`},
		{"duplicate nested key", `"kind":"chat"`, `"kind":"embedding","kind":"chat"`, `key "kind" appears twice`},
		{"duplicate role alias", `"chat-b":{`, `"chat-b":{},"chat-b":{`, `config.roles: key "chat-b" appears twice`},
		{"duplicate in a list element", `"alias":"agent-a"`, `"alias":"x","alias":"agent-a"`, `config.keys[0]: key "alias" appears twice`},
		{"case variant beside the key", `"version":"1.0"`, `"Version":"2.0","version":"1.0"`, `config: unknown key "Version"`},
		{"case variant instead of the key", `"leaves_lab":false`, `"LEAVES_LAB":false`, `unknown key "LEAVES_LAB"`},
		{"unicode fold variant", `"kind":"chat"`, `"kind":"chat","Kind":"embedding"`, "unknown key"},
	} {
		if !strings.Contains(good, c.old) {
			t.Fatalf("%s: %s not in the config", c.name, c.old)
		}
		_, err := ParseConfig([]byte(strings.Replace(good, c.old, c.new, 1)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestGatewaySecretsAtLoad(t *testing.T) {
	cfg, err := ParseConfig(mustJSON(validConfig()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSecrets(cfg, envLookup(testEnv)); err != nil {
		t.Fatal(err)
	}
	with := func(k, v string) map[string]string {
		env := map[string]string{}
		for a, b := range testEnv {
			env[a] = b
		}
		if v == "<unset>" {
			delete(env, k)
		} else {
			env[k] = v
		}
		return env
	}
	for _, c := range []struct {
		name string
		env  map[string]string
		want []string
	}{
		{"missing", with("HNX_SECRET_AGENT", "<unset>"), []string{"HNX_SECRET_AGENT is missing or empty"}},
		{"empty", with("HNX_SECRET_PROVIDER", ""), []string{"HNX_SECRET_PROVIDER is missing or empty"}},
		{"short client key", with("HNX_SECRET_LOCAL", "short-but-secret"), []string{"HNX_SECRET_LOCAL holds a key shorter than 32"}},
		{"short telemetry key", with("HNX_SECRET_TELEMETRY", "tiny"), []string{"HNX_SECRET_TELEMETRY holds a key shorter"}},
		{"short admin key", with("HNX_SECRET_ADMIN", "admin-but-only-31-bytes-long-xx"), []string{"HNX_SECRET_ADMIN holds a key shorter than 32"}},
		{"same value", with("HNX_SECRET_LOCAL", agentKey), []string{"HNX_SECRET_AGENT and HNX_SECRET_LOCAL hold the same key"}},
		{"admin same as client", with("HNX_SECRET_ADMIN", localKey), []string{"HNX_SECRET_ADMIN and HNX_SECRET_LOCAL"}},
	} {
		_, err := LoadSecrets(cfg, envLookup(c.env))
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: %v", c.name, err)
			}
		}
		for _, v := range c.env {
			if strings.Contains(err.Error(), v) && len(v) > 3 {
				t.Errorf("%s: the error names a value", c.name)
			}
		}
	}
}
