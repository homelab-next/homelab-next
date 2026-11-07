// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Schema is the shape a deployment declares for one of its profile extension keys, as data (the
// controller config's profile_extension_schemas), so a deployment needs no code linked into the
// controller to have its keys checked strictly at load. It is a small, closed subset of JSON
// Schema:
//
//	type                  one of object, array, string, integer, number, boolean, null, or a list of them
//	properties            object: name -> schema
//	additionalProperties  object: false refuses any property not in properties (true / absent allows them)
//	required              object: property names that must be present
//	items                 array: the schema every element must match
//	enum                  a non-empty list of allowed scalar values
//
// plus the annotations $schema, $id, title, description and $comment. Any other keyword is refused
// when the schema is parsed: a schema the loader cannot enforce must not look enforced.
//
// What is validated is exactly what a deployment's tools decode. A schema document holds no
// anchor, alias, merge key, repeated keyword or repeated property name. A validated value holds no
// anchor, alias or merge key (a decoder resolves them, so the checked node would not be the value
// read) and no tag outside YAML's core schema (a custom tag decodes as something else). Nesting is
// bounded (MaxSchemaDepth) in both, so neither a schema nor a value can make a load recurse
// without end.
type Schema struct {
	types      []string
	properties map[string]*Schema
	closed     bool // additionalProperties: false
	required   []string
	items      *Schema
	enum       []enumValue
	enumIsSet  bool
}

// MaxSchemaDepth bounds the nesting of a schema and of a value validated against one.
const MaxSchemaDepth = 32

var schemaTypes = map[string]bool{"object": true, "array": true, "string": true, "integer": true, "number": true, "boolean": true, "null": true}

// coreTags are the tags a validated value may carry: YAML's core schema.
// An unquoted date resolves to !!timestamp; JSON has no date type, so it validates as a string.
var coreTags = map[string]bool{"!!null": true, "!!bool": true, "!!int": true, "!!float": true, "!!str": true, "!!timestamp": true, "!!map": true, "!!seq": true}

// enumValue is one allowed enum value: its JSON Schema type and its text, so "1" (a string) and 1
// (an integer) are different values.
type enumValue struct{ kind, text string }

// ParseSchema parses a schema from its YAML (or JSON) node.
func ParseSchema(n *yaml.Node) (*Schema, error) {
	if err := plainYAML(n, "schema", 0, false); err != nil {
		return nil, err
	}
	return parseSchema(n, "", 0)
}

// plainYAML refuses anchors, aliases and merge keys under n, nesting deeper than MaxSchemaDepth
// and, with tags set, a tag outside the core schema.
func plainYAML(n *yaml.Node, where string, depth int, tags bool) error {
	if depth > MaxSchemaDepth+1 { // +1: the document node
		return fmt.Errorf("%s: nested deeper than %d", where, MaxSchemaDepth)
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("%s: YAML anchors and aliases are not allowed", where)
	}
	if tags && n.Kind != yaml.DocumentNode && !coreTags[n.ShortTag()] {
		return fmt.Errorf("%s: the YAML tag %q is not allowed", where, n.ShortTag())
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if isMergeKey(n.Content[i]) {
				return fmt.Errorf("%s: YAML merge keys (<<) are not allowed", where)
			}
		}
	}
	for _, c := range n.Content {
		if err := plainYAML(c, where, depth+1, tags); err != nil {
			return err
		}
	}
	return nil
}

func isMergeKey(k *yaml.Node) bool {
	return k.Kind == yaml.ScalarNode && (k.ShortTag() == "!!merge" || k.Value == "<<")
}

func parseSchema(n *yaml.Node, at string, depth int) (*Schema, error) {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	where := "schema"
	if at != "" {
		where = "schema at " + at
	}
	if depth > MaxSchemaDepth {
		return nil, fmt.Errorf("%s: nested deeper than %d", where, MaxSchemaDepth)
	}
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: must be a mapping", where)
	}
	s := &Schema{}
	seenKey := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i].Value, n.Content[i+1]
		if seenKey[key] {
			return nil, fmt.Errorf("%s: keyword %q appears twice", where, key)
		}
		seenKey[key] = true
		switch key {
		case "$schema", "$id", "title", "description", "$comment":
			if val.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("%s: %s must be a string", where, key)
			}
		case "type":
			switch val.Kind {
			case yaml.ScalarNode:
				s.types = []string{val.Value}
			case yaml.SequenceNode:
				for _, t := range val.Content {
					s.types = append(s.types, t.Value)
				}
			default:
				return nil, fmt.Errorf("%s: type must be a name or a list of names", where)
			}
			if len(s.types) == 0 {
				return nil, fmt.Errorf("%s: type lists no type", where)
			}
			for _, t := range s.types {
				if !schemaTypes[t] {
					return nil, fmt.Errorf("%s: unknown type %q", where, t)
				}
			}
		case "properties":
			if val.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("%s: properties must be a mapping", where)
			}
			s.properties = map[string]*Schema{}
			for j := 0; j+1 < len(val.Content); j += 2 {
				name := val.Content[j].Value
				if _, dup := s.properties[name]; dup {
					return nil, fmt.Errorf("%s: property %q appears twice", where, name)
				}
				sub, err := parseSchema(val.Content[j+1], at+"/"+name, depth+1)
				if err != nil {
					return nil, err
				}
				s.properties[name] = sub
			}
		case "additionalProperties":
			b, err := strconv.ParseBool(val.Value)
			if val.Kind != yaml.ScalarNode || val.ShortTag() != "!!bool" || err != nil {
				return nil, fmt.Errorf("%s: additionalProperties must be true or false", where)
			}
			s.closed = !b
		case "required":
			if val.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf("%s: required must be a list", where)
			}
			for _, r := range val.Content {
				if r.Kind != yaml.ScalarNode || r.ShortTag() != "!!str" || contains(s.required, r.Value) {
					return nil, fmt.Errorf("%s: required must list distinct property names", where)
				}
				s.required = append(s.required, r.Value)
			}
		case "items":
			sub, err := parseSchema(val, at+"/[]", depth+1)
			if err != nil {
				return nil, err
			}
			s.items = sub
		case "enum":
			if val.Kind != yaml.SequenceNode || len(val.Content) == 0 {
				return nil, fmt.Errorf("%s: enum must be a non-empty list", where)
			}
			s.enumIsSet = true
			for _, e := range val.Content {
				if e.Kind != yaml.ScalarNode {
					return nil, fmt.Errorf("%s: enum values must be scalars", where)
				}
				s.enum = append(s.enum, enumValue{kind: nodeType(e), text: e.Value})
			}
		default:
			return nil, fmt.Errorf("%s: keyword %q is not supported (supported: type, properties, additionalProperties, required, items, enum)", where, key)
		}
	}
	return s, nil
}

// Validate checks a profile value (its YAML node) against the schema.
func (s *Schema) Validate(n *yaml.Node) error {
	if err := plainYAML(n, "value", 0, true); err != nil {
		return err
	}
	return s.validate(n, "")
}

func (s *Schema) validate(n *yaml.Node, at string) error {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	path := at
	if path == "" {
		path = "(top)"
	}
	kind := nodeType(n)
	if len(s.types) > 0 && !typeAllowed(s.types, kind) {
		return fmt.Errorf("%s: %s is not %s", path, kind, strings.Join(s.types, " or "))
	}
	if s.enumIsSet {
		ok := false
		for _, e := range s.enum {
			if n.Kind == yaml.ScalarNode && n.Value == e.text && kind == e.kind {
				ok = true
				break
			}
		}
		if !ok {
			allowed := make([]string, len(s.enum))
			for i, e := range s.enum {
				allowed[i] = e.text + " (" + e.kind + ")"
			}
			return fmt.Errorf("%s: %q (%s) is not one of %s", path, clip(n.Value), kind, strings.Join(allowed, ", "))
		}
	}
	switch n.Kind {
	case yaml.MappingNode:
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			name := n.Content[i].Value
			if seen[name] {
				return fmt.Errorf("%s: %q appears twice", path, clip(name))
			}
			seen[name] = true
			sub := s.properties[name]
			if sub == nil {
				if s.closed {
					return fmt.Errorf("%s: field %q is not allowed (allowed: %s)", path, clip(name), strings.Join(s.propertyNames(), ", "))
				}
				continue
			}
			if err := sub.validate(n.Content[i+1], at+"/"+name); err != nil {
				return err
			}
		}
		for _, r := range s.required {
			if !seen[r] {
				return fmt.Errorf("%s: required field %q is missing", path, r)
			}
		}
	case yaml.SequenceNode:
		if s.items != nil {
			for i, e := range n.Content {
				if err := s.items.validate(e, fmt.Sprintf("%s[%d]", at, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *Schema) propertyNames() []string {
	out := make([]string, 0, len(s.properties))
	for k := range s.properties {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// nodeType is n's JSON Schema type name.
func nodeType(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		return "object"
	case yaml.SequenceNode:
		return "array"
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!null":
			return "null"
		case "!!bool":
			return "boolean"
		case "!!int":
			return "integer"
		case "!!float":
			return "number"
		default:
			return "string"
		}
	}
	return "unknown"
}

func typeAllowed(allowed []string, kind string) bool {
	for _, t := range allowed {
		if t == kind || (t == "number" && kind == "integer") {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
