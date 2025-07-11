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

func TestBasicAuthAuthenticator_GetHttpClient(t *testing.T) {
	// Skip test if TEST_KEYFACTOR_OAUTH is set to 1 or true
	if os.Getenv("TEST_KEYFACTOR_OAUTH") == "1" || os.Getenv("TEST_KEYFACTOR_OAUTH") == "true" {
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
	// Skip test if TEST_KEYFACTOR_OAUTH is set to 1 or true
	if os.Getenv("TEST_KEYFACTOR_OAUTH") == "1" || os.Getenv("TEST_KEYFACTOR_OAUTH") == "true" {
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
	// Skip test if TEST_KEYFACTOR_OAUTH is set to 1 or true
	if os.Getenv("TEST_KEYFACTOR_OAUTH") == "1" || os.Getenv("TEST_KEYFACTOR_OAUTH") == "true" {
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
	// Skip test if TEST_KEYFACTOR_OAUTH is set to 1 or true
	if os.Getenv("TEST_KEYFACTOR_OAUTH") == "1" || os.Getenv("TEST_KEYFACTOR_OAUTH") == "true" {
		t.Skip("Skipping TestBasicAuthAuthenticator_GetHttpClient")
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

	t.Log("Testing Basic Auth with Environmental variables")
	noParamsConfig := &auth_providers.CommandAuthConfigBasic{}
	authBasicTest(t, "with complete Environmental variables", false, noParamsConfig)

	t.Log("Testing Basic Auth with invalid config file path")
	invFilePath := &auth_providers.CommandAuthConfigBasic{}
	invFilePath.WithConfigFile("invalid-file-path")
	invalidPathExpectedError := []string{"no such file or directory", "invalid-file-path"}
	authBasicTest(t, "with invalid config file PATH", true, invFilePath, invalidPathExpectedError...)

	// Environment variables are not set
	t.Log("Unsetting environment variables")
	username, password, domain := exportBasicEnvVariables()
	unsetBasicEnvVariables()
	defer func() {
		t.Log("Resetting environment variables")
		setBasicEnvVariables(username, password, domain)
	}()

	t.Log("Testing Basic Auth with no Environmental variables")
	incompleteEnvConfig := &auth_providers.CommandAuthConfigBasic{}
	incompleteEnvConfigExpectedError := "username or environment variable KEYFACTOR_USERNAME is required"
	authBasicTest(
		t,
		"with incomplete Environmental variables",
		true,
		incompleteEnvConfig,
		incompleteEnvConfigExpectedError,
	)

	t.Log("Testing auth with only username")
	usernameOnlyConfig := &auth_providers.CommandAuthConfigBasic{
		Username: "test-username",
	}
	usernameOnlyConfigExceptedError := "password or environment variable KEYFACTOR_PASSWORD is required"
	authBasicTest(t, "username only", true, usernameOnlyConfig, usernameOnlyConfigExceptedError)

	t.Log("Testing auth with w/ full params variables")
	fullParamsConfig := &auth_providers.CommandAuthConfigBasic{
		Username: username,
		Password: password,
		Domain:   domain,
	}
	authBasicTest(t, "w/ full params variables", false, fullParamsConfig)

	t.Log("Testing auth with w/ full params variables")
	fullParamsinvalidPassConfig := &auth_providers.CommandAuthConfigBasic{
		Username: username,
		Password: "invalid-password",
		Domain:   domain,
	}
	invalidCredsExpectedError := []string{"401", "Unauthorized", "Access is denied due to invalid credentials"}
	authBasicTest(t, "w/ full params & invalid pass", true, fullParamsinvalidPassConfig, invalidCredsExpectedError...)

	t.Log("Testing auth with w/ no domain")
	noDomainConfig := &auth_providers.CommandAuthConfigBasic{
		Username: username,
		Password: password,
	}
	authBasicTest(t, "w/ no domain", false, noDomainConfig)

	t.Log("Testing auth with w/ no domain and no domain in username")
	usernameNoDomain := strings.Split(username, "@")[0]
	t.Logf("Username without domain: %s", usernameNoDomain)
	usernameNoDomainConfig := &auth_providers.CommandAuthConfigBasic{
		Username: usernameNoDomain,
		Password: password,
	}
	//TODO: This really SHOULD fail, but it doesn't and the auth header is sent without the domain yet it still authenticates
	authBasicTest(t, "w/o domain and no domain in username", false, usernameNoDomainConfig)

	// Write the config file back
	t.Logf("Writing config file: %s", configFilePath)
	fErr := auth_providers.WriteConfigToJSON(configFilePath, configFromFile)
	if fErr != nil {
		t.Errorf("unable to write auth config to file %s: %v", configFilePath, fErr)
	}

	t.Log("Testing Basic Auth with valid implicit config file")
	wConfigFile := &auth_providers.CommandAuthConfigBasic{}
	authBasicTest(t, "with valid implicit config file", false, wConfigFile)

	t.Log("Testing Basic Auth with invalid profile implicit config file")
	invProfile := &auth_providers.CommandAuthConfigBasic{}
	invProfile.WithConfigProfile("invalid-profile")
	expectedError := []string{"profile", "invalid-profile", "not found"}
	authBasicTest(t, "with invalid profile implicit config file", true, invProfile, expectedError...)

	t.Log("Testing Basic Auth with invalid creds implicit config file")
	invProfileCreds := &auth_providers.CommandAuthConfigBasic{}
	invProfileCreds.WithConfigProfile("invalid_username")
	authBasicTest(t, "with invalid creds implicit config file", true, invProfileCreds, invalidCredsExpectedError...)

	t.Log("Testing Basic Auth with invalid Command host implicit config file")
	invHostConfig := &auth_providers.CommandAuthConfigBasic{}
	invHostConfig.WithConfigProfile("invalid_host")
	invHostExpectedError := []string{"no such host"}
	authBasicTest(
		t, "with invalid Command host implicit config file", true, invHostConfig,
		invHostExpectedError...,
	)

	//t.Log("Testing Basic Auth with invalid config file path")
	//invFilePath := &auth_providers.CommandAuthConfigBasic{}
	//invFilePath.WithConfigFile("invalid-file-path")
	//invalidPathExpectedError := []string{"no such file or directory", "invalid-file-path"}
	//authBasicTest(t, "with invalid config file PATH", true, invFilePath, invalidPathExpectedError...)

}

func TestCommandAuthConfigBasic_Build(t *testing.T) {
	// Skip test if TEST_KEYFACTOR_OAUTH is set to 1 or true
	if os.Getenv("TEST_KEYFACTOR_OAUTH") == "1" || os.Getenv("TEST_KEYFACTOR_OAUTH") == "true" {
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

func authBasicTest(
	t *testing.T, testName string, allowFail bool, config *auth_providers.CommandAuthConfigBasic,
	errorContains ...string,
) {
	t.Run(
		fmt.Sprintf("Basic Auth Test %s", testName), func(t *testing.T) {

			err := config.Authenticate()
			if allowFail {
				if err == nil {
					t.Errorf("Basic auth test '%s' should have failed", testName)
					t.FailNow()
					return
				}
				if len(errorContains) > 0 {
					for _, ec := range errorContains {
						if !strings.Contains(err.Error(), ec) {
							t.Errorf("Basic auth test '%s' failed with unexpected error %v", testName, err)
							t.FailNow()
							return
						}
					}
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
