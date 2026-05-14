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
	"strconv"
	"strings"

	"github.com/spf13/pflag"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
)

// overlayCanonicalFields applies env-var and flag overrides on top of
// the Server unmarshalled from the config file.
//
// Why this exists: viper's UnmarshalKey doesn't traverse BindEnv /
// BindPFlag bindings into nested struct fields. Rather than fight
// viper for the nested-binding case, we read os.LookupEnv directly
// for each canonical env var and check pflag.FlagSet for explicit
// flag changes. This is deterministic and matches the precedence
// documented in the README (flag > env > file > default) by virtue
// of overlay ordering: env overlays the file first, then flags
// overlay env.
//
// Tool-namespace env vars are overlaid back into the Viper instance
// via v.Set (highest layer) so DecodeExtras sees them later.
func (l *Loader) overlayCanonicalFields(srv *auth_providers.Server, profileKey string) {
	// 1. Env overlay onto the unmarshalled Server.
	for _, b := range canonicalEnvBindings() {
		v, ok := os.LookupEnv(b.env)
		if !ok {
			continue
		}
		applyServerField(srv, b.key, v)
	}

	// 2. Flag overlay (highest precedence). Only applied for flags the
	//    user actually set on the command line.
	if l.opts.flagSet != nil {
		for _, b := range canonicalFlagBindings() {
			f := l.opts.flagSet.Lookup(b.flag)
			if f == nil || !f.Changed {
				continue
			}
			applyServerField(srv, b.key, flagValueString(f))
		}
	}

	// 3. Tool-namespace env vars are pushed back into Viper at the
	//    override layer so subsequent DecodeExtras calls see them.
	for _, t := range l.opts.tools {
		if t.envPrefix == "" || t.schema == nil {
			continue
		}
		for _, field := range schemaFields(t.schema) {
			envName := t.envPrefix + "_" + strings.ToUpper(field)
			if v, ok := os.LookupEnv(envName); ok {
				key := profileKey + "." + t.name + "." + field
				l.v.Set(key, v)
			}
		}
	}
}

// applyServerField writes the string value of a single canonical
// Server field. Conversions (int, bool) are local to this function so
// the field-name dispatch stays a single readable switch.
func applyServerField(srv *auth_providers.Server, key, raw string) {
	switch key {
	case "host":
		srv.Host = raw
	case "port":
		if i, err := strconv.Atoi(raw); err == nil {
			srv.Port = i
		}
	case "api_path":
		srv.APIPath = raw
	case "skip_tls_verify":
		srv.SkipTLSVerify = parseBool(raw)
	case "ca_cert_path":
		srv.CACertPath = raw
	case "username":
		srv.Username = raw
	case "password":
		srv.Password = raw
	case "domain":
		srv.Domain = raw
	case "client_id":
		srv.ClientID = raw
	case "client_secret":
		srv.ClientSecret = raw
	case "token_url":
		srv.OAuthTokenUrl = raw
	case "access_token":
		srv.AccessToken = raw
	case "audience":
		srv.Audience = raw
	case "scopes":
		// CSV-encoded by convention (KEYFACTOR_AUTH_SCOPES).
		srv.Scopes = splitCSV(raw)
	case "kerberos_realm":
		srv.KerberosRealm = raw
	case "kerberos_keytab":
		srv.KerberosKeytab = raw
	case "kerberos_config":
		srv.KerberosConfig = raw
	case "kerberos_ccache":
		srv.KerberosCCache = raw
	case "kerberos_spn":
		srv.KerberosSPN = raw
	}
}

func parseBool(s string) bool {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return false
	}
	return b
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// flagValueString reads the current value of a pflag.Flag as a string,
// regardless of the underlying flag type. Bool flags return "true" or
// "false"; string flags return the literal value.
func flagValueString(f *pflag.Flag) string {
	if f == nil {
		return ""
	}
	return f.Value.String()
}
