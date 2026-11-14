// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"reflect"
	"strings"
	"sync"
)

var profileKeys = sync.OnceValue(func() []string { return yamlKeys(reflect.TypeFor[Profile]()) })

// reflectProfileKeys are Profile's own top-level YAML keys.
func reflectProfileKeys() []string { return profileKeys() }

// yamlKeys are the YAML keys a struct type decodes: each exported field's tag name, without the
// ",inline" map and the "-" fields.
func yamlKeys(t reflect.Type) []string {
	var out []string
	for f := range t.Fields() {
		if !f.IsExported() {
			continue
		}
		name, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "-" || strings.Contains(opts, "inline") {
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		out = append(out, name)
	}
	return out
}
