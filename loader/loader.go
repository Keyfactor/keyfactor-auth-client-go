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

// Package loader provides a Viper-backed configuration loader for tools
// that authenticate against Keyfactor Command (and optionally other
// Keyfactor APIs).
//
// It reads the canonical Keyfactor config file layout
// (~/.keyfactor/command_config.{json,yml,yaml} with a Servers map of
// profile name → Server), merges environment variables and (optionally)
// CLI flags on top, and returns a populated auth_providers.Server.
//
// Tools that need fields beyond the canonical Server struct register a
// per-tool "namespace" — a YAML key under each Server (e.g. `acme:`,
// `kfutil:`) whose contents are decoded into a caller-supplied struct.
// Sub-block fields inherit from the server-level fields by default;
// per-field overrides are honored under strict-mode rules
// (see ResolvedAuth).
//
// The loader subpackage is the only place Viper enters the
// keyfactor-auth-client-go dependency graph. Consumers that don't
// import loader keep their slim dep tree.
package loader

import (
	"fmt"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
)

// decoderOpts configures viper.UnmarshalKey to use the existing JSON
// tags on Server (and the mapstructure tags on AuthCreds), and to
// match keys case-insensitively after stripping underscores. This
// lets `client_id` in YAML resolve to `ClientID` on Server without
// having to retag the entire struct.
func decoderOpts() viper.DecoderConfigOption {
	return func(c *mapstructure.DecoderConfig) {
		// When multiple tag names are present mapstructure prefers
		// the configured one; we use "json" because Server already
		// has full json tags. AuthCreds has explicit mapstructure
		// tags so this name will be used for it too without conflict.
		c.TagName = "json"
		// Match "client_id" to "ClientID" by lowercasing and dropping
		// underscores on both sides. The json tag handles most cases;
		// MatchName is a belt-and-suspenders for fields where mapstructure
		// reaches for the field name (e.g. `Audience` with json:"audience").
		c.MatchName = func(mapKey, fieldName string) bool {
			return normalize(mapKey) == normalize(fieldName)
		}
	}
}

func normalize(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "_", ""))
}

// Loader resolves a Keyfactor config from layered sources. The standard
// precedence is: CLI flag > environment variable > config file > caller
// defaults > zero value.
//
// A Loader is single-use: call Load once, then use the returned Server
// (and DecodeExtras / ResolvedAuth helpers) to fetch data. Constructing
// a fresh Loader for each top-level invocation keeps state simple.
type Loader struct {
	v    *viper.Viper
	opts options

	// loaded tracks whether Load has been called; subsequent calls to
	// DecodeExtras / ResolvedAuth rely on the Viper instance being
	// populated.
	loaded bool

	// resolvedProfile is the profile name picked during Load, after
	// all overrides (flag → env → option → default).
	resolvedProfile string

	// cachedServer is the fully overlaid Server produced by Load.
	// ResolvedAuth uses this rather than re-unmarshalling the Viper
	// view so that env-var and flag overrides applied in
	// overlayCanonicalFields aren't lost.
	cachedServer *auth_providers.Server
}

// New constructs a Loader. Options can be supplied in any order.
//
// With no options, the loader reads the default config file
// (~/.keyfactor/command_config.{json,yml,yaml}, with the discovery
// order matching kfc-auth's existing convention), selects the
// "default" profile or whatever KEYFACTOR_AUTH_CONFIG_PROFILE names,
// and binds the canonical KEYFACTOR_* / KEYFACTOR_AUTH_* env vars to
// their server-level fields.
func New(opts ...Option) *Loader {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	v := viper.New()
	v.SetConfigType("yaml") // overridden by ConfigType inference in Load
	return &Loader{v: v, opts: o}
}

// Load resolves the active profile from all layers and returns the
// populated Server. The returned Server's Extras map contains every
// registered tool namespace, ready for DecodeExtras.
//
// Load performs no authentication and no URL/host validation; the
// caller validates whatever it needs (typically AuthCreds.Validate()
// from auth_providers plus its own URL checks).
func (l *Loader) Load() (*auth_providers.Server, error) {
	if l.loaded {
		return nil, fmt.Errorf("loader.Load already called; construct a fresh Loader for a new resolution")
	}

	// 1. Resolve the config file path. Search order:
	//      explicit --config flag (caller-bound) >
	//      WithConfigFile option >
	//      KEYFACTOR_AUTH_CONFIG_FILE env >
	//      ~/.keyfactor/command_config.{json,yml,yaml}.
	path, err := l.discoverConfigFile()
	if err != nil {
		return nil, err
	}
	if path != "" {
		l.v.SetConfigFile(path)
		if err := l.v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config file %q: %w", path, err)
		}
	}

	// 2. Bind canonical environment variables. Tool-namespace env vars
	//    are bound after we know the active profile so we can target
	//    the right Viper key path.
	l.bindCanonicalEnv()

	// 3. Bind CLI flags from any registered pflag.FlagSet.
	if err := l.bindFlags(); err != nil {
		return nil, err
	}

	// 4. Apply caller-provided defaults at the lowest precedence layer.
	for k, val := range l.opts.defaults {
		l.v.SetDefault(k, val)
	}

	// 5. Resolve the active profile name.
	l.resolvedProfile = l.resolveProfile()

	// 6. Bind tool-namespace env vars now that the profile is known.
	l.bindToolEnvs()

	// 7. Unmarshal the active profile into a Server. We allow the
	//    profile to be absent so callers can construct a Server from
	//    pure env/flag input (common in CI).
	key := "servers." + l.resolvedProfile
	var srv auth_providers.Server
	if err := l.v.UnmarshalKey(key, &srv, decoderOpts()); err != nil {
		return nil, fmt.Errorf("unmarshal profile %q: %w", l.resolvedProfile, err)
	}

	// 8. Overlay env vars and flags onto the Server. Viper's
	//    UnmarshalKey does NOT traverse BindEnv / BindPFlag into
	//    nested struct fields, so we apply the overrides explicitly
	//    using v.IsSet checks (which DO honor env/flag bindings).
	//    Precedence within Viper itself stays flag > env > file, so
	//    a single v.GetString per leaf gives the right value.
	l.overlayCanonicalFields(&srv, key)

	l.cachedServer = &srv
	l.loaded = true
	return &srv, nil
}

// Profile reports the active profile name. Valid only after Load.
func (l *Loader) Profile() string {
	return l.resolvedProfile
}

// Viper returns the underlying *viper.Viper instance. Exposed for
// advanced callers that need to query keys directly; most consumers
// should prefer DecodeExtras and ResolvedAuth.
func (l *Loader) Viper() *viper.Viper {
	return l.v
}
