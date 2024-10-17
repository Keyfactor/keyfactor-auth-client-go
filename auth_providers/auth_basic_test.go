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
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
)

func TestBasicAuthAuthenticator_GetHttpClient(t *testing.T) {
	// Skip test if TEST_KEYFACTOR_KC_AUTH is set to 1 or true
	if os.Getenv("TEST_KEYFACTOR_KC_AUTH") == "1" || os.Getenv("TEST_KEYFACTOR_KC_AUTH") == "true" {
		t.Skip("Skipping TestBasicAuthAuthenticator_GetHttpClient")
		return
	}

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
	// Skip test if TEST_KEYFACTOR_KC_AUTH is set to 1 or true
	if os.Getenv("TEST_KEYFACTOR_KC_AUTH") == "1" || os.Getenv("TEST_KEYFACTOR_KC_AUTH") == "true" {
		t.Skip("Skipping TestBasicAuthAuthenticator_GetHttpClient")
		return
	}
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
	// Skip test if TEST_KEYFACTOR_KC_AUTH is set to 1 or true
	if os.Getenv("TEST_KEYFACTOR_KC_AUTH") == "1" || os.Getenv("TEST_KEYFACTOR_KC_AUTH") == "true" {
		t.Skip("Skipping TestBasicAuthAuthenticator_GetHttpClient")
		return
	}

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
	// Skip test if TEST_KEYFACTOR_KC_AUTH is set to 1 or true
	if os.Getenv("TEST_KEYFACTOR_KC_AUTH") == "1" || os.Getenv("TEST_KEYFACTOR_KC_AUTH") == "true" {
		t.Skip("Skipping TestBasicAuthAuthenticator_GetHttpClient")
		return
	}

	noParamsConfig := &auth_providers.CommandAuthConfigBasic{}
	authBasicTest(t, "with complete Environmental variables", false, noParamsConfig)

	// Environment variables are not set
	t.Log("Unsetting environment variables")
	username, password, domain := exportBasicEnvVariables()
	unsetBasicEnvVariables()

	incompleteEnvConfig := &auth_providers.CommandAuthConfigBasic{}
	authBasicTest(t, "with incomplete Environmental variables", true, incompleteEnvConfig)

	usernameOnlyConfig := &auth_providers.CommandAuthConfigBasic{
		Username: "test-username",
	}
	authBasicTest(t, "Username Only", true, usernameOnlyConfig)

	fullParamsConfig := &auth_providers.CommandAuthConfigBasic{
		Username: username,
		Password: password,
		Domain:   domain,
	}
	authBasicTest(t, "w/ full params variables", false, fullParamsConfig)
	t.Log("Resetting environment variables")
	setBasicEnvVariables(username, password, domain)
}

func TestCommandAuthConfigBasic_Build(t *testing.T) {
	// Skip test if TEST_KEYFACTOR_KC_AUTH is set to 1 or true
	if os.Getenv("TEST_KEYFACTOR_KC_AUTH") == "1" || os.Getenv("TEST_KEYFACTOR_KC_AUTH") == "true" {
		t.Skip("Skipping TestBasicAuthAuthenticator_GetHttpClient")
		return
	}
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

// setBasicEnvVariables sets the basic environment variables
func setBasicEnvVariables(username, password, domain string) {
	os.Setenv(auth_providers.EnvKeyfactorUsername, username)
	os.Setenv(auth_providers.EnvKeyfactorPassword, password)
	os.Setenv(auth_providers.EnvKeyfactorDomain, domain)
}

// exportBasicEnvVariables sets the basic environment variables
func exportBasicEnvVariables() (string, string, string) {
	username := os.Getenv(auth_providers.EnvKeyfactorUsername)
	password := os.Getenv(auth_providers.EnvKeyfactorPassword)
	domain := os.Getenv(auth_providers.EnvKeyfactorDomain)
	return username, password, domain
}

// unsetBasicEnvVariables unsets the basic environment variables
func unsetBasicEnvVariables() {
	os.Unsetenv(auth_providers.EnvKeyfactorUsername)
	os.Unsetenv(auth_providers.EnvKeyfactorPassword)
	os.Unsetenv(auth_providers.EnvKeyfactorDomain)
}

func authBasicTest(t *testing.T, testName string, allowFail bool, config *auth_providers.CommandAuthConfigBasic) {
	t.Run(
		fmt.Sprintf("Basic Auth Test %s", testName), func(t *testing.T) {

			err := config.Authenticate()
			if allowFail {
				if err == nil {
					t.Errorf("Basic auth test '%s' should have failed", testName)
					t.FailNow()
					return
				}
				t.Logf("Basic auth test '%s' failed as expected with %v", testName, err)
				return
			}
			if err != nil {
				t.Errorf("Basic auth test '%s' failed with %v", testName, err)
				t.FailNow()
				return
			}
		},
	)
}
