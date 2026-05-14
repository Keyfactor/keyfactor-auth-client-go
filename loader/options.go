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
	"github.com/spf13/pflag"
)

// Option configures a Loader at construction time. Options are
// composable and order-independent.
type Option func(*options)

// toolNamespace is a registration record produced by WithToolNamespace.
// The schema parameter is optional; when supplied, its mapstructure
// tags are introspected to bind <EnvPrefix>_<TAG_UPPER> env vars to the
// corresponding sub-block fields under the active profile.
type toolNamespace struct {
	name      string // YAML key (e.g. "acme")
	envPrefix string // env-var prefix (e.g. "KEYFACTOR_ACME"); empty disables env binding
	schema    any    // optional reflection target for env-suffix derivation
}

type options struct {
	configFile string
	profile    string
	flagSet    *pflag.FlagSet
	defaults   map[string]any
	tools      []toolNamespace

	// pendingCanonicalEnv is the list of canonical kfc-auth env vars to
	// bind once the active profile is known (the profile name is part
	// of the Viper key path). Populated by bindCanonicalEnv in env.go.
	pendingCanonicalEnv []envBinding

	// pendingFlagBindings is the analogous deferred-binding list for
	// pflag-bound flags from the caller's FlagSet.
	pendingFlagBindings []pendingFlagBinding
}

// pendingFlagBinding records a server-level flag that should be bound
// under servers.<profile>.<key> once resolveProfile runs.
type pendingFlagBinding struct {
	flag *pflag.Flag
	key  string
}

func defaultOptions() options {
	return options{
		defaults: make(map[string]any),
	}
}

// WithConfigFile pins a specific config file path, bypassing
// auto-discovery. Equivalent to setting the KEYFACTOR_AUTH_CONFIG_FILE
// env var or passing --config-file at the CLI layer (when a flag set
// is registered).
func WithConfigFile(path string) Option {
	return func(o *options) { o.configFile = path }
}

// WithProfile selects which profile under `servers:` to read. When
// unset, the loader falls back to KEYFACTOR_AUTH_CONFIG_PROFILE and
// then to "default".
func WithProfile(name string) Option {
	return func(o *options) { o.profile = name }
}

// WithFlagSet binds a pflag.FlagSet so that registered flag values
// participate in precedence at the highest layer. Cobra-based tools
// typically pass cmd.PersistentFlags() or cmd.Flags().
//
// The loader binds the canonical Keyfactor flag names (--base-url,
// --hostname, --username, --password, --client-id, --client-secret,
// --token-url, --access-token, --scopes, --audience, --skip-verify,
// --api-path, --profile, --config-file). Flags absent from the set
// are silently ignored.
func WithFlagSet(fs *pflag.FlagSet) Option {
	return func(o *options) { o.flagSet = fs }
}

// WithDefaults seeds defaults for known fields. Defaults occupy the
// lowest precedence layer; any value from the file, env, or flag wins.
//
// Keys are dotted Viper paths relative to the active profile. To set
// a default for every profile use the top-level form
// "servers.default.skip_tls_verify"; to set just one profile use
// "servers.<profile>.<field>".
func WithDefaults(defaults map[string]any) Option {
	return func(o *options) {
		for k, v := range defaults {
			o.defaults[k] = v
		}
	}
}

// WithToolNamespace registers a per-tool sub-block schema. The
// namespace is the YAML key under each Server (e.g. "acme"). When
// envPrefix is non-empty, env vars matching <envPrefix>_<FIELD>
// (uppercased) are bound to sub-block fields under the active profile.
//
// If schema is non-nil, its mapstructure tags are walked to derive
// the env-suffix → field-name map. When schema is nil, env binding
// for the namespace is disabled — callers can still read sub-block
// fields from the config file via DecodeExtras.
//
// Tools typically register their namespace at startup:
//
//	type ACMEConfig struct {
//	    BaseURL string `mapstructure:"base_url"`
//	    Output  string `mapstructure:"output"`
//	}
//
//	l := loader.New(
//	    loader.WithToolNamespace("acme", "KEYFACTOR_ACME", &ACMEConfig{}),
//	)
func WithToolNamespace(name, envPrefix string, schema any) Option {
	return func(o *options) {
		o.tools = append(o.tools, toolNamespace{
			name:      name,
			envPrefix: envPrefix,
			schema:    schema,
		})
	}
}
