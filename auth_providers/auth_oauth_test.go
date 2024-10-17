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
