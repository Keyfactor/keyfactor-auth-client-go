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

// canonicalFlagBindings maps the standard Keyfactor CLI flag names to
// their dotted Viper keys relative to a Server. Flags absent from the
// caller-supplied FlagSet are silently ignored so consumers can opt
// into whichever subset they expose.
//
// Flag names follow the existing Keyfactor convention (hyphenated) for
// the CLI surface, while the underlying Viper keys use underscores to
// match the canonical file format.
func canonicalFlagBindings() []flagBinding {
	return []flagBinding{
		// Connection target.
		{flag: "hostname", key: "host"},
		{flag: "base-url", key: "host"}, // kfacme-cli compatibility alias
		{flag: "port", key: "port"},
		{flag: "api-path", key: "api_path"},
		{flag: "skip-verify", key: "skip_tls_verify"},
		{flag: "ca-cert", key: "ca_cert_path"},

		// Basic auth.
		{flag: "username", key: "username"},
		{flag: "password", key: "password"},
		{flag: "domain", key: "domain"},

		// OAuth2.
		{flag: "client-id", key: "client_id"},
		{flag: "client-secret", key: "client_secret"},
		{flag: "token-url", key: "token_url"},
		{flag: "access-token", key: "access_token"},
		{flag: "scopes", key: "scopes"},
		{flag: "audience", key: "audience"},

		// Kerberos.
		{flag: "kerberos-realm", key: "kerberos_realm"},
		{flag: "kerberos-keytab", key: "kerberos_keytab"},
		{flag: "kerberos-config", key: "kerberos_config"},
		{flag: "kerberos-ccache", key: "kerberos_ccache"},
		{flag: "kerberos-spn", key: "kerberos_spn"},
	}
}

type flagBinding struct {
	flag string // pflag name (hyphenated)
	key  string // Viper sub-key under servers.<profile>
}

// bindFlags wires every recognized flag in the registered FlagSet to
// its corresponding server-level Viper key. Profile-selection and
// config-file flags are bound to synthetic top-level keys; the
// resolveProfile and discoverConfigFile steps consume them.
//
// Returns nil when no FlagSet was registered. Errors only on a viper
// binding failure (which in practice doesn't happen for non-nil flag
// objects).
func (l *Loader) bindFlags() error {
	fs := l.opts.flagSet
	if fs == nil {
		return nil
	}

	// Profile and config-file flags target synthetic top-level keys
	// (no profile prefix). resolveProfile / discoverConfigFile consume
	// them.
	if f := fs.Lookup("profile"); f != nil {
		if err := l.v.BindPFlag("active_profile", f); err != nil {
			return err
		}
	}
	if f := fs.Lookup("config-file"); f != nil {
		if err := l.v.BindPFlag("active_config_file", f); err != nil {
			return err
		}
	} else if f := fs.Lookup("config"); f != nil { // common short form
		if err := l.v.BindPFlag("active_config_file", f); err != nil {
			return err
		}
	}

	// Canonical server-level flags bind under the active profile path.
	// At this point the profile may not be resolved yet, so we defer
	// the binding until after resolveProfile runs, just like canonical
	// env vars do. Stash the pairs that have matching flags now and
	// apply them in applyFlagBindingsForProfile.
	for _, b := range canonicalFlagBindings() {
		if f := fs.Lookup(b.flag); f != nil {
			l.opts.pendingFlagBindings = append(l.opts.pendingFlagBindings,
				pendingFlagBinding{flag: f, key: b.key})
		}
	}
	return nil
}

// applyFlagBindingsForProfile finalizes the server-level flag bindings
// now that the active profile name is known. Called from the body of
// resolveProfile via the same mechanism as canonical env vars.
func (l *Loader) applyFlagBindingsForProfile() {
	for _, b := range l.opts.pendingFlagBindings {
		full := "servers." + l.resolvedProfile + "." + b.key
		_ = l.v.BindPFlag(full, b.flag)
	}
}
