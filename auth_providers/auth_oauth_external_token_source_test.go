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

// This file scaffolds the test surface for caller-supplied external oauth2.TokenSource
// support, per docs/design/external-token-source.md. It is written against
// CommandConfigOauth.WithExternalTokenSource, which does not exist yet, and is expected to
// fail to compile until that implementation lands. Once it compiles, the conflict test and
// the "no ClientID required" happy path are also expected to keep failing until
// ValidateAuthConfig's credential-source handling is generalized per §4 of the design doc
// (today it unconditionally requires a ClientID whenever AccessToken is unset).
package auth_providers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
)

// clearOAuthEnv snapshots and clears the ClientID/ClientSecret/TokenURL-related env vars
// (via the exportOAuthEnvVariables/unsetOAuthEnvVariables/setOAuthEnvVariables helpers
// already defined in auth_oauth_test.go) so ambient CI/dev-environment configuration can't
// leak into these external-token-source tests, restoring them on cleanup.
func clearOAuthEnv(t *testing.T) {
	t.Helper()

	clientID, clientSecret, tokenURL := exportOAuthEnvVariables()
	unsetOAuthEnvVariables()
	t.Cleanup(
		func() {
			setOAuthEnvVariables(clientID, clientSecret, tokenURL)
		},
	)
}

// mockTokenSource is a minimal oauth2.TokenSource test double, standing in for whatever
// ambient-credential mechanism a real caller (e.g. command-cert-manager-issuer under
// workload identity) would supply.
type mockTokenSource struct {
	token *oauth2.Token
	err   error
	calls atomic.Int32
}

func (m *mockTokenSource) Token() (*oauth2.Token, error) {
	m.calls.Add(1)
	if m.err != nil {
		return nil, m.err
	}
	return m.token, nil
}

// newStatusEndpointsServer returns an httptest.Server standing in for Command's
// Status/Endpoints health-check endpoint (what CommandAuthConfig.Authenticate() calls),
// capturing the Authorization header of each request it receives.
func newStatusEndpointsServer(t *testing.T, captured *[]string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				*captured = append(*captured, r.Header.Get("Authorization"))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode([]string{})
			},
		),
	)
}

// TestCommandConfigOauth_ExternalTokenSource_ValidateAndAuthenticate covers the primary
// external-token-source path from docs/design/external-token-source.md: a caller-supplied
// oauth2.TokenSource (standing in for an ambient/workload-identity credential) should be
// enough on its own for ValidateAuthConfig to succeed and for Authenticate to complete a real
// request carrying whatever token the source produced -- no ClientID/ClientSecret/TokenURL
// required.
func TestCommandConfigOauth_ExternalTokenSource_ValidateAndAuthenticate(t *testing.T) {
	clearOAuthEnv(t)

	const wantToken = "external-token-abc123"
	mockSource := &mockTokenSource{
		token: &oauth2.Token{
			AccessToken: wantToken,
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(time.Hour),
		},
	}

	var capturedAuthHeaders []string
	server := newStatusEndpointsServer(t, &capturedAuthHeaders)
	defer server.Close()

	config := &auth_providers.CommandConfigOauth{}
	config.WithExternalTokenSource(mockSource)
	config.WithCommandHostName(server.URL)

	if err := config.ValidateAuthConfig(); err != nil {
		t.Fatalf("expected ValidateAuthConfig to succeed with only an ExternalTokenSource configured, got %v", err)
	}

	if err := config.Authenticate(); err != nil {
		t.Fatalf("expected Authenticate to succeed, got %v", err)
	}

	if len(capturedAuthHeaders) == 0 {
		t.Fatalf("expected the fake Command server to receive at least one request")
	}
	want := "Bearer " + wantToken
	for _, got := range capturedAuthHeaders {
		if got != want {
			t.Errorf("expected Authorization header %q, got %q", want, got)
		}
	}

	if mockSource.calls.Load() == 0 {
		t.Errorf("expected the external token source to have been called at least once")
	}
}

// The SDK must wrap the caller-supplied source (e.g. via oauth2.ReuseTokenSourceWithExpiry) rather
// than calling it on every outgoing request, exactly like the existing ClientSecret flow's
// token reuse (see TestCommandConfigOauth_TokenSourceIsReused in auth_oauth_test.go).
func TestCommandConfigOauth_ExternalTokenSource_Reused(t *testing.T) {
	clearOAuthEnv(t)

	mockSource := &mockTokenSource{
		token: &oauth2.Token{
			AccessToken: "reused-token",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(time.Hour),
		},
	}

	var capturedAuthHeaders []string
	server := newStatusEndpointsServer(t, &capturedAuthHeaders)
	defer server.Close()

	config := &auth_providers.CommandConfigOauth{}
	config.WithExternalTokenSource(mockSource)
	config.WithCommandHostName(server.URL)

	const numRequests = 3
	for i := 0; i < numRequests; i++ {
		client, err := config.GetHttpClient()
		if err != nil {
			t.Fatalf("GetHttpClient() call %d failed: %v", i+1, err)
		}
		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("request %d failed: %v", i+1, err)
		}
		resp.Body.Close()
	}

	if got := mockSource.calls.Load(); got != 1 {
		t.Errorf(
			"expected the external token source to be called exactly once across %d requests, got %d calls -- it is not being reused/cached",
			numRequests, got,
		)
	}
}

// TestCommandConfigOauth_GetAccessToken_ExternalTokenSource covers GetAccessToken() directly
// (as opposed to GetHttpClient()/Authenticate()) with only an ExternalTokenSource configured
// -- no ClientID/ClientSecret/TokenURL at all -- and asserts the token it returns is exactly
// the one the mock source produced.
func TestCommandConfigOauth_GetAccessToken_ExternalTokenSource(t *testing.T) {
	clearOAuthEnv(t)

	wantExpiry := time.Now().Add(time.Hour)
	mockSource := &mockTokenSource{
		token: &oauth2.Token{
			AccessToken: "external-token-abc123",
			TokenType:   "Bearer",
			Expiry:      wantExpiry,
		},
	}

	config := &auth_providers.CommandConfigOauth{}
	config.WithExternalTokenSource(mockSource)
	config.WithCommandHostName("idp.example.com")

	token, err := config.GetAccessToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if token == nil {
		t.Fatalf("expected a non-nil token")
	}
	if token.AccessToken != "external-token-abc123" {
		t.Errorf("expected AccessToken %q, got %q", "external-token-abc123", token.AccessToken)
	}
	if !token.Expiry.Equal(wantExpiry) {
		t.Errorf("expected Expiry %v, got %v", wantExpiry, token.Expiry)
	}
	if mockSource.calls.Load() != 1 {
		t.Errorf("expected the external token source to be called exactly once, got %d calls", mockSource.calls.Load())
	}
}

// Validates error propagation when the caller-supplied source itself fails -- it must surface that
// failure rather than falling through to the "client ID, client secret, and token URL must
// be provided" error meant for the client_credentials path.
func TestCommandConfigOauth_GetAccessToken_ExternalTokenSourceError(t *testing.T) {
	clearOAuthEnv(t)

	wantErr := fmt.Errorf("ambient credential provider unavailable")
	mockSource := &mockTokenSource{err: wantErr}

	config := &auth_providers.CommandConfigOauth{}
	config.WithExternalTokenSource(mockSource)
	config.WithCommandHostName("idp.example.com")

	token, err := config.GetAccessToken()
	if err == nil {
		t.Fatalf("expected an error, got a token: %+v", token)
	}
	if !strings.Contains(err.Error(), wantErr.Error()) {
		t.Errorf("expected error to wrap %q, got: %v", wantErr.Error(), err)
	}
	if strings.Contains(err.Error(), "client ID, client secret, and token URL") {
		t.Errorf("got the client_credentials-path error instead of the external-token-source error: %v", err)
	}
}
