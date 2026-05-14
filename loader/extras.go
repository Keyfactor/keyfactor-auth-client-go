// Copyright 2026 Keyfactor
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package loader

import (
	"fmt"
)

// DecodeExtras unmarshals the per-tool sub-block named `namespace`
// (e.g. "acme") into target. target must be a non-nil pointer to a
// struct whose fields have `mapstructure` tags matching the YAML keys
// under the sub-block.
//
// When the sub-block is absent, DecodeExtras returns nil and leaves
// target untouched. Callers that require the sub-block should check
// for zero values afterwards.
//
// DecodeExtras can only be called after Load.
func (l *Loader) DecodeExtras(namespace string, target any) error {
	if !l.loaded {
		return fmt.Errorf("loader.DecodeExtras called before Load")
	}
	if namespace == "" {
		return fmt.Errorf("loader.DecodeExtras requires a non-empty namespace")
	}
	if target == nil {
		return fmt.Errorf("loader.DecodeExtras requires a non-nil target")
	}
	key := "servers." + l.resolvedProfile + "." + namespace
	if !l.v.IsSet(key) {
		return nil
	}
	if err := l.v.UnmarshalKey(key, target, decoderOpts()); err != nil {
		return fmt.Errorf("decode sub-block %q: %w", namespace, err)
	}
	return nil
}
