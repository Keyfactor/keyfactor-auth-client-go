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

package loader_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/Keyfactor/keyfactor-auth-client-go/loader"
)

// acmeSchema is the kfacme-cli sub-block shape. Defined inside the
// test package because the loader itself stays schema-agnostic.
type acmeSchema struct {
	BaseURL string `mapstructure:"base_url"`
	Output  string `mapstructure:"output"`
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return p
}

// TestLoad_SharedCreds covers the common case: one OAuth2 tuple at the
// server level, used by both Command-targeting tools and the ACME
// sub-block via inheritance.
func TestLoad_SharedCreds(t *testing.T) {
	l := loader.New(loader.WithConfigFile(fixture(t, "shared_creds.yaml")))
	srv, err := l.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := srv.Host, "command.example.com"; got != want {
		t.Errorf("Host: got %q, want %q", got, want)
	}
	if got, want := srv.ClientID, "shared-svc"; got != want {
		t.Errorf("ClientID: got %q, want %q", got, want)
	}

	// Server-level auth view validates as oauth2.
	got, err := l.ResolvedAuth("")
	if err != nil {
		t.Fatalf("ResolvedAuth(\"\"): %v", err)
	}
	if got.ClientID != "shared-svc" || got.ClientSecret != "shared-rotate" {
		t.Errorf("server-level creds not populated: %+v", got)
	}

	// ACME view inherits the same auth tuple (sub-block has no auth
	// fields, so strict-mode falls through to inheritance).
	gotAcme, err := l.ResolvedAuth("acme")
	if err != nil {
		t.Fatalf("ResolvedAuth(\"acme\"): %v", err)
	}
	if gotAcme.ClientID != "shared-svc" {
		t.Errorf("acme creds did not inherit: %+v", gotAcme)
	}

	// Sub-block decodes into the consumer's struct.
	var acme acmeSchema
	if err := l.DecodeExtras("acme", &acme); err != nil {
		t.Fatalf("DecodeExtras: %v", err)
	}
	if acme.BaseURL != "https://acme.example.com/acme-admin" {
		t.Errorf("acme.BaseURL: got %q", acme.BaseURL)
	}
}

// TestLoad_SeparateCreds covers the case where the sub-block declares
// its own full OAuth2 tuple. The sub-block creds must win for the
// "acme" namespace; the server-level creds must remain intact for the
// empty namespace.
func TestLoad_SeparateCreds(t *testing.T) {
	l := loader.New(loader.WithConfigFile(fixture(t, "separate_creds.yaml")))
	if _, err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	gotCommand, err := l.ResolvedAuth("")
	if err != nil {
		t.Fatalf("ResolvedAuth(\"\"): %v", err)
	}
	if gotCommand.ClientID != "command-svc" {
		t.Errorf("command creds: %+v", gotCommand)
	}

	gotAcme, err := l.ResolvedAuth("acme")
	if err != nil {
		t.Fatalf("ResolvedAuth(\"acme\"): %v", err)
	}
	if gotAcme.ClientID != "acme-svc" || gotAcme.ClientSecret != "acme-rotate" {
		t.Errorf("acme creds did not override: %+v", gotAcme)
	}
	if gotAcme.TokenURL != "https://acme-auth.customer.com/oauth/token" {
		t.Errorf("acme token_url did not override: %+v", gotAcme)
	}
}

// TestLoad_ACMEOnly verifies that profiles without Command target
// fields still resolve cleanly. The auth tuple is complete; the
// caller (kfacme-cli) is responsible for checking its own URL field
// later.
func TestLoad_ACMEOnly(t *testing.T) {
	l := loader.New(loader.WithConfigFile(fixture(t, "acme_only.yaml")))
	srv, err := l.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if srv.Host != "" {
		t.Errorf("expected empty Host, got %q", srv.Host)
	}

	// Server-level auth is the inherited tuple; should validate as
	// oauth2 even though Host is empty (loader doesn't enforce hosts).
	if _, err := l.ResolvedAuth(""); err != nil {
		t.Fatalf("server-level auth should validate on an ACME-only profile: %v", err)
	}

	var acme acmeSchema
	if err := l.DecodeExtras("acme", &acme); err != nil {
		t.Fatalf("DecodeExtras: %v", err)
	}
	if acme.BaseURL == "" {
		t.Error("acme.base_url should be populated")
	}
}

// TestLoad_MixedMethods covers the case where the sub-block uses a
// different auth method (static token) than the server level (OAuth2).
func TestLoad_MixedMethods(t *testing.T) {
	l := loader.New(loader.WithConfigFile(fixture(t, "mixed_methods.yaml")))
	if _, err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Command auth is oauth2.
	gotCmd, err := l.ResolvedAuth("")
	if err != nil {
		t.Fatalf("ResolvedAuth(\"\"): %v", err)
	}
	if gotCmd.AccessToken != "" {
		t.Errorf("command should not see acme's static token: %+v", gotCmd)
	}

	// ACME auth is the static bearer ONLY — strict mode means the
	// OAuth2 fields don't leak in.
	gotAcme, err := l.ResolvedAuth("acme")
	if err != nil {
		t.Fatalf("ResolvedAuth(\"acme\"): %v", err)
	}
	if gotAcme.AccessToken == "" {
		t.Errorf("acme should see its static token: %+v", gotAcme)
	}
	if gotAcme.ClientID != "" {
		t.Errorf("strict mode: acme should NOT inherit command's client_id: %+v", gotAcme)
	}

	method, err := gotAcme.Validate()
	if err != nil {
		t.Fatalf("acme creds should validate as token: %v", err)
	}
	if method != auth_providers.AuthMethodToken {
		t.Errorf("acme method: got %q, want token", method)
	}
}

// TestLoad_PartialOverrideRejected covers strict mode: a sub-block
// that declares an OAuth2 tuple but omits client_secret must error
// with a clear message.
func TestLoad_PartialOverrideRejected(t *testing.T) {
	l := loader.New(loader.WithConfigFile(fixture(t, "partial_override.yaml")))
	if _, err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	_, err := l.ResolvedAuth("acme")
	if err == nil {
		t.Fatal("expected an error for partial override; got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "client_secret") {
		t.Errorf("expected error to mention client_secret; got: %s", msg)
	}
	if !strings.Contains(msg, "acme") {
		t.Errorf("expected error to mention the acme namespace; got: %s", msg)
	}
}

// TestLoad_ProfileSelection verifies the WithProfile option targets a
// non-default profile correctly.
func TestLoad_ProfileSelection(t *testing.T) {
	l := loader.New(
		loader.WithConfigFile(fixture(t, "shared_creds.yaml")),
		loader.WithProfile("staging"),
	)
	srv, err := l.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if srv.Host != "command-staging.example.com" {
		t.Errorf("Host: got %q, want command-staging.example.com", srv.Host)
	}
	if l.Profile() != "staging" {
		t.Errorf("Profile: got %q, want staging", l.Profile())
	}
}

// TestLoad_EnvOverride verifies that env vars override file values
// for canonical kfc-auth fields.
func TestLoad_EnvOverride(t *testing.T) {
	t.Setenv(auth_providers.EnvKeyfactorClientSecret, "from-env")

	l := loader.New(loader.WithConfigFile(fixture(t, "shared_creds.yaml")))
	if _, err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, err := l.ResolvedAuth("")
	if err != nil {
		t.Fatalf("ResolvedAuth: %v", err)
	}
	if got.ClientSecret != "from-env" {
		t.Errorf("env should override file: got %q, want from-env", got.ClientSecret)
	}
}

// TestLoad_ToolEnvBinding verifies that registering a tool namespace
// with an env prefix binds the tool's sub-block fields.
func TestLoad_ToolEnvBinding(t *testing.T) {
	t.Setenv("KEYFACTOR_ACME_BASE_URL", "https://from-env.example.com/acme")

	l := loader.New(
		loader.WithConfigFile(fixture(t, "shared_creds.yaml")),
		loader.WithToolNamespace("acme", "KEYFACTOR_ACME", &acmeSchema{}),
	)
	if _, err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	var acme acmeSchema
	if err := l.DecodeExtras("acme", &acme); err != nil {
		t.Fatalf("DecodeExtras: %v", err)
	}
	if acme.BaseURL != "https://from-env.example.com/acme" {
		t.Errorf("tool env should override file: got %q", acme.BaseURL)
	}
}

// TestAuthCreds_Validate sanity-checks the validator covers every
// auth method and rejects an empty tuple.
func TestAuthCreds_Validate(t *testing.T) {
	cases := []struct {
		name    string
		creds   auth_providers.AuthCreds
		want    auth_providers.AuthMethod
		wantErr bool
	}{
		{"empty", auth_providers.AuthCreds{}, auth_providers.AuthMethodUnset, true},
		{
			"basic complete",
			auth_providers.AuthCreds{Username: "u", Password: "p"},
			auth_providers.AuthMethodBasic, false,
		},
		{
			"basic missing password",
			auth_providers.AuthCreds{Username: "u"},
			auth_providers.AuthMethodUnset, true,
		},
		{
			"oauth2 complete",
			auth_providers.AuthCreds{ClientID: "c", ClientSecret: "s", TokenURL: "u"},
			auth_providers.AuthMethodOAuth2, false,
		},
		{
			"oauth2 missing token_url",
			auth_providers.AuthCreds{ClientID: "c", ClientSecret: "s"},
			auth_providers.AuthMethodUnset, true,
		},
		{
			"token",
			auth_providers.AuthCreds{AccessToken: "t"},
			auth_providers.AuthMethodToken, false,
		},
		{
			"kerberos keytab",
			auth_providers.AuthCreds{KerberosKeytab: "/etc/krb5.keytab"},
			auth_providers.AuthMethodKerberos, false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.creds.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err: got %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("method: got %q, want %q", got, tc.want)
			}
		})
	}
}
