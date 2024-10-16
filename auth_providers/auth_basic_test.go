package auth_providers_test

import (
	"net/http"
	"os"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
)

func TestBasicAuthAuthenticator_GetHttpClient(t *testing.T) {
	auth := &auth_providers.BasicAuthAuthenticator{
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

func TestCommandAuthConfigBasic_ValidateAuthConfig(t *testing.T) {
	config := &auth_providers.CommandAuthConfigBasic{
		Username: os.Getenv(auth_providers.EnvKeyfactorUsername),
		Password: os.Getenv(auth_providers.EnvKeyfactorPassword),
	}

	err := config.ValidateAuthConfig()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCommandAuthConfigBasic_GetHttpClient(t *testing.T) {
	config := &auth_providers.CommandAuthConfigBasic{
		Username: os.Getenv(auth_providers.EnvKeyfactorUsername),
		Password: os.Getenv(auth_providers.EnvKeyfactorPassword),
	}

	client, err := config.GetHttpClient()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if client == nil {
		t.Fatalf("expected a non-nil http.Client")
	}
}

func TestCommandAuthConfigBasic_Authenticate(t *testing.T) {
	config := &auth_providers.CommandAuthConfigBasic{}

	err := config.Authenticate()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCommandAuthConfigBasic_Build(t *testing.T) {
	config := &auth_providers.CommandAuthConfigBasic{
		Username: os.Getenv(auth_providers.EnvKeyfactorUsername),
		Password: os.Getenv(auth_providers.EnvKeyfactorPassword),
	}

	authenticator, err := config.Build()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if authenticator == nil {
		t.Fatalf("expected a non-nil Authenticator")
	}
}
