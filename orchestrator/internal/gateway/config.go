// SPDX-License-Identifier: Apache-2.0

// Package gateway is the lab's LLM gateway (ADR-0038): role aliases in front of
// OpenAI-compatible and Anthropic backends, with per-key scope, per-request TLP admission,
// sliding-window limits, ordered failover, role fallbacks and a content-free usage log. The
// config shape is the gateway config contract v1.0 (gateway/gateway.json).
package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
)

// Config is gateway/gateway.json. Every field but conformance_only is required (a null is
// spelled out); unknown keys are refused at every level.
type Config struct {
	Version         string           `json:"version"`
	Name            string           `json:"name"`
	AdminKeyEnv     string           `json:"admin_key_env"`
	Roles           map[string]*Role `json:"roles"`
	Keys            []*Key           `json:"keys"`
	TelemetryReader *TelemetryReader `json:"telemetry_reader"`
	// ConformanceOnly marks a config rendered with the renderer's test-only option (ADR-0038 d7): the
	// gateway serves it only when started with -conformance. The one optional key.
	ConformanceOnly bool `json:"conformance_only,omitempty"`
}

// Role is one role alias.
type Role struct {
	Kind             string        `json:"kind"`
	MaxContextTokens *int          `json:"max_context_tokens"`
	TLPCeiling       string        `json:"tlp_ceiling"`
	LeavesLab        bool          `json:"leaves_lab"`
	Deployments      []*Deployment `json:"deployments"`
	Fallbacks        []string      `json:"fallbacks"`
	Limits           *RoleLimits   `json:"limits"`
	CostPer1KTokens  *float64      `json:"cost_per_1k_tokens"`

	alias   string
	ceiling Label
}

// Deployment is one backend serving a role.
type Deployment struct {
	ID        string  `json:"id"`
	Backend   string  `json:"backend"`
	Locality  string  `json:"locality"`
	Protocol  string  `json:"protocol"`
	BaseURL   string  `json:"base_url"`
	Model     string  `json:"model"`
	APIKeyEnv *string `json:"api_key_env"`
}

// RoleLimits is one budget for a whole role, across all its deployments.
type RoleLimits struct {
	WindowS     int      `json:"window_s"`
	MaxRequests *int     `json:"max_requests"`
	MaxTokens   *int     `json:"max_tokens"`
	MaxCost     *float64 `json:"max_cost"`
}

// KeyLimits is one budget for a key (no cost per key in v1).
type KeyLimits struct {
	WindowS     int  `json:"window_s"`
	MaxRequests *int `json:"max_requests"`
	MaxTokens   *int `json:"max_tokens"`
}

// Key is one caller key.
type Key struct {
	Alias      string     `json:"alias"`
	KeyEnv     string     `json:"key_env"`
	Owner      string     `json:"owner"`
	DataTier   string     `json:"data_tier"`
	TLPCeiling string     `json:"tlp_ceiling"`
	Roles      []string   `json:"roles"`
	Limits     *KeyLimits `json:"limits"`

	ceiling Label
	roleSet map[string]bool
}

// TelemetryReader is the key that may read /v1/usage and nothing else.
type TelemetryReader struct {
	KeyEnv string `json:"key_env"`
}

// ConfigError lists every problem found; it never holds a secret value.
type ConfigError struct{ Problems []string }

func (e *ConfigError) Error() string {
	return "gateway config refused:\n  - " + strings.Join(e.Problems, "\n  - ")
}

// LoadConfig reads and validates the config file at path.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(data)
}

// ParseConfig decodes data strictly (unknown keys, missing keys, trailing data) and validates
// every rule of the contract.
func ParseConfig(data []byte) (*Config, error) {
	// encoding/json keeps the last of two equal keys and matches field names case-insensitively,
	// so a duplicate or a case variant would be read silently: refuse both before decoding.
	if err := uniqueKeys(data); err != nil {
		return nil, &ConfigError{[]string{"not a gateway config: " + err.Error()}}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, &ConfigError{[]string{"not a gateway config: " + err.Error()}}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, &ConfigError{[]string{"not a gateway config: data after the top-level object"}}
	}
	var probs []string
	if err := missingFields(data, reflect.TypeOf(c), "config", &probs); err != nil {
		return nil, &ConfigError{[]string{"not a gateway config: " + err.Error()}}
	}
	if len(probs) == 0 {
		probs = c.validate()
	}
	if len(probs) > 0 {
		return nil, &ConfigError{probs}
	}
	return &c, nil
}

// missingFields reports every struct field absent from the JSON (the contract spells out
// nulls, so an absent key is a renderer that does not match this reader).
func missingFields(data []byte, t reflect.Type, path string, probs *[]string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		tags := map[string]bool{}
		for i := 0; i < t.NumField(); i++ {
			if f := t.Field(i); f.IsExported() {
				name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
				tags[name] = true
			}
		}
		for _, k := range sortedKeys(obj) {
			if !tags[k] {
				// DisallowUnknownFields lets a case variant through: keys must be the exact tag
				*probs = append(*probs, fmt.Sprintf("%s: unknown key %q (keys are matched exactly)", path, k))
			}
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
			if !f.IsExported() || name == "" || opts == "omitempty" {
				continue // omitempty marks the contract's optional keys
			}
			raw, ok := obj[name]
			if !ok {
				*probs = append(*probs, fmt.Sprintf("%s: missing %q", path, name))
				continue
			}
			if err := missingFields(raw, f.Type, path+"."+name, probs); err != nil {
				return err
			}
		}
	case reflect.Map:
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		for k, raw := range obj {
			if err := missingFields(raw, t.Elem(), path+"."+k, probs); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var arr []json.RawMessage
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		for i, raw := range arr {
			if err := missingFields(raw, t.Elem(), fmt.Sprintf("%s[%d]", path, i), probs); err != nil {
				return err
			}
		}
	}
	return nil
}

// Role returns the role with this alias, or nil.
func (c *Config) Role(alias string) *Role { return c.Roles[alias] }

// Alias is the role's alias.
func (r *Role) Alias() string { return r.alias }

// Ceiling is the role's TLP ceiling.
func (r *Role) Ceiling() Label { return r.ceiling }

// Ceiling is the key's sending TLP ceiling.
func (k *Key) Ceiling() Label { return k.ceiling }

// Allows says whether the key may call the role.
func (k *Key) Allows(role string) bool { return k.roleSet[role] }

// uniqueKeys walks every token of data and refuses an object that has the same key twice, at any
// level (the roles map included).
func uniqueKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return uniqueKeysValue(dec, "config")
}

func uniqueKeysValue(dec *json.Decoder, path string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			k, _ := kt.(string)
			if seen[k] {
				return fmt.Errorf("%s: key %q appears twice", path, k)
			}
			seen[k] = true
			if err := uniqueKeysValue(dec, path+"."+k); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case json.Delim('['):
		for i := 0; dec.More(); i++ {
			if err := uniqueKeysValue(dec, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	}
	return nil
}
