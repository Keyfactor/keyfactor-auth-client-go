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

package auth_providers

import (
	"fmt"
	"strings"
)

// AuthMethod is the credential family that satisfies a Keyfactor auth
// request. Returned by AuthCreds.Validate.
type AuthMethod string

const (
	// AuthMethodUnset means no complete credential tuple was found.
	AuthMethodUnset AuthMethod = ""
	// AuthMethodBasic requires Username + Password (and optionally Domain).
	AuthMethodBasic AuthMethod = "basic"
	// AuthMethodOAuth2 requires ClientID + ClientSecret + TokenURL.
	AuthMethodOAuth2 AuthMethod = "oauth2"
	// AuthMethodToken requires AccessToken (a static bearer).
	AuthMethodToken AuthMethod = "token"
	// AuthMethodKerberos requires at least one of:
	//   KerberosKeytab,
	//   KerberosCCache,
	//   (Username + Password + KerberosRealm).
	AuthMethodKerberos AuthMethod = "kerberos"
)

// AuthCreds is the auth-only view of a Server, decoupled from Command
// target fields (Host/Port/APIPath). It lets callers validate
// credentials independently of whether they're targeting Command,
// ACME, or anything else.
//
// AuthCreds is intentionally a flat struct so it round-trips cleanly
// through Viper / mapstructure. The loader subpackage uses it for
// sub-block override merging.
type AuthCreds struct {
	// AuthType is an optional explicit method selector ("basic",
	// "oauth2", "token", "kerberos"). When set it disambiguates
	// otherwise-overlapping inputs (e.g. an OAuth2 client_id and a
	// static AccessToken set on the same profile). When unset,
	// Validate infers the method from which fields are populated.
	AuthType string `mapstructure:"auth_type" json:"auth_type,omitempty" yaml:"auth_type,omitempty"`

	// Basic
	Username string `mapstructure:"username" json:"username,omitempty" yaml:"username,omitempty"`
	Password string `mapstructure:"password" json:"password,omitempty" yaml:"password,omitempty"`
	Domain   string `mapstructure:"domain" json:"domain,omitempty" yaml:"domain,omitempty"`

	// OAuth2 client credentials
	ClientID     string   `mapstructure:"client_id" json:"client_id,omitempty" yaml:"client_id,omitempty"`
	ClientSecret string   `mapstructure:"client_secret" json:"client_secret,omitempty" yaml:"client_secret,omitempty"`
	TokenURL     string   `mapstructure:"token_url" json:"token_url,omitempty" yaml:"token_url,omitempty"`
	Scopes       []string `mapstructure:"scopes" json:"scopes,omitempty" yaml:"scopes,omitempty"`
	Audience     string   `mapstructure:"audience" json:"audience,omitempty" yaml:"audience,omitempty"`

	// Static bearer
	AccessToken string `mapstructure:"access_token" json:"access_token,omitempty" yaml:"access_token,omitempty"`

	// Kerberos
	KerberosRealm  string `mapstructure:"kerberos_realm" json:"kerberos_realm,omitempty" yaml:"kerberos_realm,omitempty"`
	KerberosKeytab string `mapstructure:"kerberos_keytab" json:"kerberos_keytab,omitempty" yaml:"kerberos_keytab,omitempty"`
	KerberosConfig string `mapstructure:"kerberos_config" json:"kerberos_config,omitempty" yaml:"kerberos_config,omitempty"`
	KerberosCCache string `mapstructure:"kerberos_ccache" json:"kerberos_ccache,omitempty" yaml:"kerberos_ccache,omitempty"`
	KerberosSPN    string `mapstructure:"kerberos_spn" json:"kerberos_spn,omitempty" yaml:"kerberos_spn,omitempty"`
}

// AuthCredsFromServer extracts the credential fields from a Server into
// a standalone AuthCreds. Used by the loader to build the server-level
// view before applying per-tool sub-block overrides.
func AuthCredsFromServer(s *Server) *AuthCreds {
	if s == nil {
		return &AuthCreds{}
	}
	return &AuthCreds{
		AuthType:       s.AuthType,
		Username:       s.Username,
		Password:       s.Password,
		Domain:         s.Domain,
		ClientID:       s.ClientID,
		ClientSecret:   s.ClientSecret,
		TokenURL:       s.OAuthTokenUrl,
		Scopes:         append([]string(nil), s.Scopes...),
		Audience:       s.Audience,
		AccessToken:    s.AccessToken,
		KerberosRealm:  s.KerberosRealm,
		KerberosKeytab: s.KerberosKeytab,
		KerberosConfig: s.KerberosConfig,
		KerberosCCache: s.KerberosCCache,
		KerberosSPN:    s.KerberosSPN,
	}
}

// Validate reports whether the credentials form a complete tuple for
// some auth method, and returns the resolved method.
//
// Method selection rules (first match wins):
//   1. If AuthType is set, it forces the chosen method; all required
//      fields for that method must be present.
//   2. Otherwise, the first method whose required fields are fully
//      populated is selected.
//
// Validation is strict: a partially-populated method (e.g. ClientID
// without ClientSecret) returns an error naming the missing fields
// even when another method would have been complete. This catches
// configuration mistakes early.
func (a *AuthCreds) Validate() (AuthMethod, error) {
	if a == nil {
		return AuthMethodUnset, fmt.Errorf("auth credentials are nil")
	}

	// What's populated, by method.
	hasBasic := a.Username != "" || a.Password != ""
	hasOAuth2 := a.ClientID != "" || a.ClientSecret != "" || a.TokenURL != ""
	hasToken := a.AccessToken != ""
	hasKerberos := a.KerberosRealm != "" || a.KerberosKeytab != "" || a.KerberosCCache != "" || a.KerberosSPN != ""

	// Forced by AuthType.
	if a.AuthType != "" {
		switch strings.ToLower(a.AuthType) {
		case string(AuthMethodBasic):
			return AuthMethodBasic, validateBasic(a)
		case string(AuthMethodOAuth2):
			return AuthMethodOAuth2, validateOAuth2(a)
		case string(AuthMethodToken):
			return AuthMethodToken, validateToken(a)
		case string(AuthMethodKerberos):
			return AuthMethodKerberos, validateKerberos(a)
		default:
			return AuthMethodUnset, fmt.Errorf("unknown auth_type %q (expected basic, oauth2, token, or kerberos)", a.AuthType)
		}
	}

	// Strict-mode partial detection: if a method's first field is set
	// but the rest are not, it's an error even if another method would
	// have validated. This makes "I forgot client_secret" produce a
	// clear message instead of silently falling through.
	if hasOAuth2 {
		if err := validateOAuth2(a); err != nil {
			return AuthMethodUnset, err
		}
		return AuthMethodOAuth2, nil
	}
	if hasBasic {
		if err := validateBasic(a); err != nil {
			return AuthMethodUnset, err
		}
		return AuthMethodBasic, nil
	}
	if hasToken {
		// Token only needs AccessToken; validateToken is just a
		// non-empty check.
		return AuthMethodToken, validateToken(a)
	}
	if hasKerberos {
		if err := validateKerberos(a); err != nil {
			return AuthMethodUnset, err
		}
		return AuthMethodKerberos, nil
	}

	return AuthMethodUnset, fmt.Errorf("no auth credentials configured (set username/password, client_id/client_secret/token_url, access_token, or a Kerberos tuple)")
}

func validateBasic(a *AuthCreds) error {
	var missing []string
	if a.Username == "" {
		missing = append(missing, "username")
	}
	if a.Password == "" {
		missing = append(missing, "password")
	}
	if len(missing) > 0 {
		return fmt.Errorf("basic auth missing required field(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

func validateOAuth2(a *AuthCreds) error {
	var missing []string
	if a.ClientID == "" {
		missing = append(missing, "client_id")
	}
	if a.ClientSecret == "" {
		missing = append(missing, "client_secret")
	}
	if a.TokenURL == "" {
		missing = append(missing, "token_url")
	}
	if len(missing) > 0 {
		return fmt.Errorf("oauth2 auth missing required field(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

func validateToken(a *AuthCreds) error {
	if a.AccessToken == "" {
		return fmt.Errorf("token auth missing required field: access_token")
	}
	return nil
}

func validateKerberos(a *AuthCreds) error {
	// Kerberos accepts any of: keytab, ccache, or username+password+realm.
	if a.KerberosKeytab != "" || a.KerberosCCache != "" {
		return nil
	}
	if a.Username != "" && a.Password != "" && a.KerberosRealm != "" {
		return nil
	}
	return fmt.Errorf("kerberos auth requires one of: kerberos_keytab, kerberos_ccache, or (username + password + kerberos_realm)")
}
