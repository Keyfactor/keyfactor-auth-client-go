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
	"strings"
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
	userHome, hErr := os.UserHomeDir()
	if hErr != nil {
		userHome = os.Getenv("HOME")
	}

	configFilePath := fmt.Sprintf("%s/%s", userHome, auth_providers.DefaultConfigFilePath)
	configFromFile, cErr := auth_providers.ReadConfigFromJSON(configFilePath)
	if cErr != nil {
		t.Errorf("unable to load auth config from file %s: %v", configFilePath, cErr)
	}

	if configFromFile == nil || configFromFile.Servers == nil {
		t.Errorf("invalid config file %s", configFilePath)
		t.FailNow()
	}

	// Delete the config file
	t.Logf("Deleting config file: %s", configFilePath)
	os.Remove(configFilePath)
	defer func() {
		// Write the config file back
		t.Logf("Writing config file: %s", configFilePath)
		fErr := auth_providers.WriteConfigToJSON(configFilePath, configFromFile)
		if fErr != nil {
			t.Errorf("unable to write auth config to file %s: %v", configFilePath, fErr)
		}
	}()

	t.Log("Testing oAuth with Environmental variables")
	noParamsConfig := &auth_providers.CommandConfigOauth{}
	authOauthTest(t, "with complete Environmental variables", false, noParamsConfig)

	t.Log("Testing oAuth with invalid config file path")
	invFilePath := &auth_providers.CommandConfigOauth{}
	invFilePath.WithConfigFile("invalid-file-path")
	invalidPathExpectedError := []string{"no such file or directory", "invalid-file-path"}
	authOauthTest(t, "with invalid config file PATH", true, invFilePath, invalidPathExpectedError...)

	// Environment variables are not set
	t.Log("Unsetting environment variables")
	clientID, clientSecret, tokenURL := exportOAuthEnvVariables()
	unsetOAuthEnvVariables()
	defer func() {
		t.Log("Resetting environment variables")
		setOAuthEnvVariables(clientID, clientSecret, tokenURL)
	}()

	t.Log("Testing oAuth with no Environmental variables")
	incompleteEnvConfig := &auth_providers.CommandConfigOauth{}
	incompleteEnvConfigExpectedError := fmt.Sprintf(
		"client ID or environment variable %s is required",
		auth_providers.EnvKeyfactorClientID,
	)
	authOauthTest(
		t,
		"with incomplete Environmental variables",
		true,
		incompleteEnvConfig,
		incompleteEnvConfigExpectedError,
	)

	t.Log("Testing auth with only clientID")
	clientIDOnlyConfig := &auth_providers.CommandConfigOauth{
		ClientID: "test-client-id",
	}
	clientIDOnlyConfigExceptedError := fmt.Sprintf(
		"client secret or environment variable %s is required",
		auth_providers.EnvKeyfactorClientSecret,
	)
	authOauthTest(t, "clientID only", true, clientIDOnlyConfig, clientIDOnlyConfigExceptedError)

	t.Log("Testing auth with w/ full params variables")
	fullParamsConfig := &auth_providers.CommandConfigOauth{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
	}
	authOauthTest(t, "w/ full params variables", false, fullParamsConfig)

	t.Log("Testing auth with w/ full params & invalid pass")
	fullParamsInvalidPassConfig := &auth_providers.CommandConfigOauth{
		ClientID:     clientID,
		ClientSecret: "invalid-client-secret",
		TokenURL:     tokenURL,
	}
	invalidCredsExpectedError := []string{
		"oauth2", "unauthorized_client", "Invalid client or Invalid client credentials",
	}
	authOauthTest(t, "w/ full params & invalid pass", true, fullParamsInvalidPassConfig, invalidCredsExpectedError...)

	t.Log("Testing auth with w/ no tokenURL")
	noTokenURLConfig := &auth_providers.CommandConfigOauth{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	noTokenURLExpectedError := fmt.Sprintf(
		"token URL or environment variable %s is required",
		auth_providers.EnvKeyfactorAuthTokenURL,
	)
	authOauthTest(t, "w/ no tokenURL", true, noTokenURLConfig, noTokenURLExpectedError)

	// Write the config file back
	t.Logf("Writing config file: %s", configFilePath)
	fErr := auth_providers.WriteConfigToJSON(configFilePath, configFromFile)
	if fErr != nil {
		t.Errorf("unable to write auth config to file %s: %v", configFilePath, fErr)
	}

	t.Log("Testing oAuth with valid implicit config file")
	wConfigFile := &auth_providers.CommandConfigOauth{}
	wConfigFile.WithConfigProfile("oauth")
	authOauthTest(t, "with valid implicit config file", false, wConfigFile)

	t.Log("Testing oAuth with invalid profile implicit config file")
	invProfile := &auth_providers.CommandConfigOauth{}
	invProfile.WithConfigProfile("invalid-profile")
	expectedError := []string{"profile", "invalid-profile", "not found"}
	authOauthTest(t, "with invalid profile implicit config file", true, invProfile, expectedError...)

	t.Log("Testing oAuth with invalid creds implicit config file")
	invProfileCreds := &auth_providers.CommandConfigOauth{}
	invProfileCreds.WithConfigProfile("oauth_invalid_creds")
	authOauthTest(t, "with invalid creds implicit config file", true, invProfileCreds, invalidCredsExpectedError...)

	t.Log("Testing oAuth with invalid Command host implicit config file")
	invCmdHost := &auth_providers.CommandConfigOauth{}
	invCmdHost.WithConfigProfile("oauth_invalid_host")
	invHostExpectedError := []string{"no such host"}
	authOauthTest(t, "with invalid creds implicit config file", true, invCmdHost, invHostExpectedError...)
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

func authOauthTest(
	t *testing.T, testName string, allowFail bool, config *auth_providers.CommandConfigOauth,
	errorContains ...string,
) {
	t.Run(
		fmt.Sprintf("oAuth Auth Test %s", testName), func(t *testing.T) {

			err := config.Authenticate()
			if allowFail {
				if err == nil {
					t.Errorf("oAuth auth test '%s' should have failed", testName)
					t.FailNow()
					return
				}
				if len(errorContains) > 0 {
					for _, ec := range errorContains {
						if !strings.Contains(err.Error(), ec) {
							t.Errorf("oAuth auth test '%s' failed with unexpected error %v", testName, err)
							t.FailNow()
							return
						}
					}
				}
				t.Logf("oAuth auth test '%s' failed as expected with %v", testName, err)
				return
			}
			if err != nil {
				t.Errorf("oAuth auth test '%s' failed with %v", testName, err)
				t.FailNow()
				return
			}
		},
	)
}

// setOAuthEnvVariables sets the oAuth environment variables
func setOAuthEnvVariables(client_id, client_secret, token_url string) {
	os.Setenv(auth_providers.EnvKeyfactorClientID, client_id)
	os.Setenv(auth_providers.EnvKeyfactorClientSecret, client_secret)
	os.Setenv(auth_providers.EnvKeyfactorAuthTokenURL, token_url)
}

// exportOAuthEnvVariables sets the oAuth environment variables
func exportOAuthEnvVariables() (string, string, string) {
	client_id := os.Getenv(auth_providers.EnvKeyfactorClientID)
	client_secret := os.Getenv(auth_providers.EnvKeyfactorClientSecret)
	token_url := os.Getenv(auth_providers.EnvKeyfactorAuthTokenURL)
	return client_id, client_secret, token_url
}

// unsetOAuthEnvVariables unsets the oAuth environment variables
func unsetOAuthEnvVariables() {
	os.Unsetenv(auth_providers.EnvKeyfactorClientID)
	os.Unsetenv(auth_providers.EnvKeyfactorClientSecret)
	os.Unsetenv(auth_providers.EnvKeyfactorAuthTokenURL)
}
