// Copyright 2024 Keyfactor
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

package auth_providers_test

import (
	"net/http"
	"os"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
)

func TestOAuthAuthenticator_GetHttpClient(t *testing.T) {
	// Skip test if TEST_KEYFACTOR_AD_AUTH is set to 1 or true
	if os.Getenv("TEST_KEYFACTOR_AD_AUTH") == "1" || os.Getenv("TEST_KEYFACTOR_AD_AUTH") == "true" {
		t.Skip("Skipping TestOAuthAuthenticator_GetHttpClient")
		return
	}
	auth := &auth_providers.OAuthAuthenticator{
		Client: &http.Client{},
	}

	client, err := auth.GetHttpClient()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if client == nil {
		t.Fatalf("expected a non-nil http.Client")
	}
}

func TestCommandConfigOauth_ValidateAuthConfig(t *testing.T) {
	// Skip test if TEST_KEYFACTOR_AD_AUTH is set to 1 or true
	if os.Getenv("TEST_KEYFACTOR_AD_AUTH") == "1" || os.Getenv("TEST_KEYFACTOR_AD_AUTH") == "true" {
		t.Skip("Skipping TestOAuthAuthenticator_GetHttpClient")
		return
	}
	config := &auth_providers.CommandConfigOauth{
		ClientID:     os.Getenv(auth_providers.EnvKeyfactorClientID),
		ClientSecret: os.Getenv(auth_providers.EnvKeyfactorClientSecret),
		TokenURL:     os.Getenv(auth_providers.EnvKeyfactorAuthTokenURL),
	}

	err := config.ValidateAuthConfig()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCommandConfigOauth_GetHttpClient(t *testing.T) {
	// Skip test if TEST_KEYFACTOR_AD_AUTH is set to 1 or true
	if os.Getenv("TEST_KEYFACTOR_AD_AUTH") == "1" || os.Getenv("TEST_KEYFACTOR_AD_AUTH") == "true" {
		t.Skip("Skipping TestOAuthAuthenticator_GetHttpClient")
		return
	}
	config := &auth_providers.CommandConfigOauth{
		ClientID:     os.Getenv(auth_providers.EnvKeyfactorClientID),
		ClientSecret: os.Getenv(auth_providers.EnvKeyfactorClientSecret),
		TokenURL:     os.Getenv(auth_providers.EnvKeyfactorAuthTokenURL),
		Scopes:       []string{"openid", "profile", "email"},
	}

	client, err := config.GetHttpClient()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if client == nil {
		t.Fatalf("expected a non-nil http.Client")
	}
}

func TestCommandConfigOauth_Authenticate(t *testing.T) {
	// Skip test if TEST_KEYFACTOR_AD_AUTH is set to 1 or true
	if os.Getenv("TEST_KEYFACTOR_AD_AUTH") == "1" || os.Getenv("TEST_KEYFACTOR_AD_AUTH") == "true" {
		t.Skip("Skipping TestOAuthAuthenticator_GetHttpClient")
		return
	}
	config := &auth_providers.CommandConfigOauth{
		ClientID:     os.Getenv(auth_providers.EnvKeyfactorClientID),
		ClientSecret: os.Getenv(auth_providers.EnvKeyfactorClientSecret),
		TokenURL:     os.Getenv(auth_providers.EnvKeyfactorAuthTokenURL),
		Scopes:       []string{"openid", "profile", "email"},
	}

	err := config.Authenticate()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCommandConfigOauth_Build(t *testing.T) {
	// Skip test if TEST_KEYFACTOR_AD_AUTH is set to 1 or true
	if os.Getenv("TEST_KEYFACTOR_AD_AUTH") == "1" || os.Getenv("TEST_KEYFACTOR_AD_AUTH") == "true" {
		t.Skip("Skipping TestOAuthAuthenticator_GetHttpClient")
		return
	}
	config := &auth_providers.CommandConfigOauth{
		ClientID:     os.Getenv(auth_providers.EnvKeyfactorClientID),
		ClientSecret: os.Getenv(auth_providers.EnvKeyfactorClientSecret),
		TokenURL:     os.Getenv(auth_providers.EnvKeyfactorAuthTokenURL),
		Scopes:       []string{"openid", "profile", "email"},
	}

	authenticator, err := config.Build()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if authenticator == nil {
		t.Fatalf("expected a non-nil Authenticator")
	}
}
