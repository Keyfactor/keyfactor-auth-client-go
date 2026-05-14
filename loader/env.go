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
	"os"
	"reflect"
	"strings"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
)

// canonicalEnvBindings maps the existing kfc-auth env var constants to
// their dotted Viper keys relative to a Server. Bound under
// servers.<profile>.* during Load.
//
// Order intentionally mirrors auth_core.go / auth_basic.go /
// auth_oauth.go / auth_kerberos.go so a reader can cross-reference.
func canonicalEnvBindings() []envBinding {
	return []envBinding{
		// auth_core.go
		{key: "host", env: auth_providers.EnvKeyfactorHostName},
		{key: "port", env: auth_providers.EnvKeyfactorPort},
		{key: "api_path", env: auth_providers.EnvKeyfactorAPIPath},
		{key: "skip_tls_verify", env: auth_providers.EnvKeyfactorSkipVerify},
		{key: "ca_cert_path", env: auth_providers.EnvKeyfactorCACert},

		// auth_basic.go
		{key: "username", env: auth_providers.EnvKeyfactorUsername},
		{key: "password", env: auth_providers.EnvKeyfactorPassword},
		{key: "domain", env: auth_providers.EnvKeyfactorDomain},

		// auth_oauth.go
		{key: "client_id", env: auth_providers.EnvKeyfactorClientID},
		{key: "client_secret", env: auth_providers.EnvKeyfactorClientSecret},
		{key: "token_url", env: auth_providers.EnvKeyfactorAuthTokenURL},
		{key: "access_token", env: auth_providers.EnvKeyfactorAccessToken},
		{key: "audience", env: auth_providers.EnvKeyfactorAuthAudience},
		{key: "scopes", env: auth_providers.EnvKeyfactorAuthScopes},

		// auth_kerberos.go
		{key: "kerberos_realm", env: auth_providers.EnvKeyfactorKrbRealm},
		{key: "kerberos_keytab", env: auth_providers.EnvKeyfactorKrbKeytab},
		{key: "kerberos_config", env: auth_providers.EnvKeyfactorKrbConfig},
		{key: "kerberos_ccache", env: auth_providers.EnvKeyfactorKrbCCache},
		{key: "kerberos_spn", env: auth_providers.EnvKeyfactorKrbSPN},
	}
}

type envBinding struct {
	key string // Viper sub-key under servers.<profile>, e.g. "host"
	env string // environment variable name
}

// bindCanonicalEnv wires the kfc-auth standard env vars to their
// server-level keys for the active profile. Called from Load.
//
// We bind via explicit BindEnv (one call per var) rather than
// AutomaticEnv because the profile name is part of the Viper key path
// and we need to compose it deterministically.
func (l *Loader) bindCanonicalEnv() {
	// Profile selector env var is bound to a synthetic top-level key
	// used only by resolveProfile.
	_ = l.v.BindEnv("active_profile", auth_providers.EnvKeyfactorAuthProfile)

	// Canonical bindings need a profile path; defer the actual binding
	// until resolveProfile has run by re-binding from there. For now,
	// stash them so resolveProfile can apply them once it knows the
	// active profile.
	l.opts.pendingCanonicalEnv = canonicalEnvBindings()
}

// applyCanonicalEnvForProfile binds the canonical env vars under the
// concrete profile path now that l.resolvedProfile is set.
func (l *Loader) applyCanonicalEnvForProfile() {
	for _, b := range l.opts.pendingCanonicalEnv {
		full := "servers." + l.resolvedProfile + "." + b.key
		_ = l.v.BindEnv(full, b.env)
	}
}

// bindToolEnvs walks each registered tool namespace and, if the
// caller supplied an envPrefix and a schema, binds
// <envPrefix>_<FIELD_UPPER> for every mapstructure-tagged field in the
// schema. Field names with embedded dots are NOT supported; flat
// structs work cleanly.
func (l *Loader) bindToolEnvs() {
	for _, t := range l.opts.tools {
		if t.envPrefix == "" || t.schema == nil {
			continue
		}
		fields := schemaFields(t.schema)
		for _, field := range fields {
			envName := t.envPrefix + "_" + strings.ToUpper(field)
			viperKey := "servers." + l.resolvedProfile + "." + t.name + "." + field
			_ = l.v.BindEnv(viperKey, envName)
		}
	}
}

// schemaFields introspects a struct (or pointer to struct) and returns
// the lowercase mapstructure tag (or field name) for every top-level
// field. Embedded fields and nested structs are not recursed — tool
// sub-blocks should be flat. Fields with `mapstructure:"-"` are
// skipped.
func schemaFields(schema any) []string {
	t := reflect.TypeOf(schema)
	if t == nil {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	out := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("mapstructure")
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		out = append(out, name)
	}
	return out
}

// resolveProfile picks the active profile name. Precedence:
//
//	WithProfile option > KEYFACTOR_AUTH_CONFIG_PROFILE > "default"
func (l *Loader) resolveProfile() string {
	if l.opts.profile != "" {
		l.applyCanonicalEnvForProfile_setProfile(l.opts.profile)
		return l.opts.profile
	}
	if envVal := os.Getenv(auth_providers.EnvKeyfactorAuthProfile); envVal != "" {
		l.applyCanonicalEnvForProfile_setProfile(envVal)
		return envVal
	}
	l.applyCanonicalEnvForProfile_setProfile(auth_providers.DefaultConfigProfile)
	return auth_providers.DefaultConfigProfile
}

// applyCanonicalEnvForProfile_setProfile is a tiny helper that stashes
// the resolved profile and applies all deferred bindings — canonical
// env vars and pflag-bound flags. Split out so resolveProfile reads
// cleanly.
func (l *Loader) applyCanonicalEnvForProfile_setProfile(profile string) {
	l.resolvedProfile = profile
	l.applyCanonicalEnvForProfile()
	l.applyFlagBindingsForProfile()
}
