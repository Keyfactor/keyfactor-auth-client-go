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

package auth_providers_test

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
)

func TestKerberosAuthenticator_GetHttpClient(t *testing.T) {
	// Skip test if TEST_KEYFACTOR_KRB_AUTH is not set
	if os.Getenv("TEST_KEYFACTOR_KRB_AUTH") != "1" && os.Getenv("TEST_KEYFACTOR_KRB_AUTH") != "true" {
		t.Skip("Skipping TestKerberosAuthenticator_GetHttpClient - set TEST_KEYFACTOR_KRB_AUTH=true to run")
		return
	}

	auth := &auth_providers.KerberosAuthenticator{
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

func TestCommandAuthConfigKerberos_ValidateAuthConfig(t *testing.T) {
	// Skip test if TEST_KEYFACTOR_KRB_AUTH is not set
	if os.Getenv("TEST_KEYFACTOR_KRB_AUTH") != "1" && os.Getenv("TEST_KEYFACTOR_KRB_AUTH") != "true" {
		t.Skip("Skipping TestCommandAuthConfigKerberos_ValidateAuthConfig - set TEST_KEYFACTOR_KRB_AUTH=true to run")
		return
	}

	config := &auth_providers.CommandAuthConfigKerberos{
		Username:   os.Getenv(auth_providers.EnvKeyfactorKrbUsername),
		Password:   os.Getenv(auth_providers.EnvKeyfactorKrbPassword),
		Realm:      os.Getenv(auth_providers.EnvKeyfactorKrbRealm),
		ConfigPath: os.Getenv(auth_providers.EnvKeyfactorKrbConfig),
	}

	err := config.ValidateAuthConfig()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCommandAuthConfigKerberos_WithBuilderMethods(t *testing.T) {
	// This test doesn't require Kerberos infrastructure
	config := auth_providers.NewKerberosAuthenticatorBuilder().
		WithUsername("testuser").
		WithPassword("testpass").
		WithRealm("TEST.REALM").
		WithConfigPath("/etc/krb5.conf").
		WithKeytabPath("/path/to/keytab").
		WithCCachePath("/tmp/krb5cc_1000").
		WithSPN("HTTP/server.example.com").
		WithDisablePAFXFast(true)

	if config == nil {
		t.Fatalf("expected a non-nil config")
	}

	// Verify builder methods work correctly (access via GetServerConfig)
	serverConfig := config.GetServerConfig()

	if serverConfig.Username != "testuser" {
		t.Errorf("expected username 'testuser', got '%s'", serverConfig.Username)
	}
	if serverConfig.Password != "testpass" {
		t.Errorf("expected password 'testpass', got '%s'", serverConfig.Password)
	}
	if serverConfig.KerberosRealm != "TEST.REALM" {
		t.Errorf("expected realm 'TEST.REALM', got '%s'", serverConfig.KerberosRealm)
	}
	if serverConfig.KerberosConfig != "/etc/krb5.conf" {
		t.Errorf("expected config path '/etc/krb5.conf', got '%s'", serverConfig.KerberosConfig)
	}
	if serverConfig.KerberosKeytab != "/path/to/keytab" {
		t.Errorf("expected keytab path '/path/to/keytab', got '%s'", serverConfig.KerberosKeytab)
	}
	if serverConfig.KerberosCCache != "/tmp/krb5cc_1000" {
		t.Errorf("expected ccache path '/tmp/krb5cc_1000', got '%s'", serverConfig.KerberosCCache)
	}
	if serverConfig.KerberosSPN != "HTTP/server.example.com" {
		t.Errorf("expected SPN 'HTTP/server.example.com', got '%s'", serverConfig.KerberosSPN)
	}
	if serverConfig.AuthType != "kerberos" {
		t.Errorf("expected auth type 'kerberos', got '%s'", serverConfig.AuthType)
	}
}

func TestCommandAuthConfigKerberos_RealmNormalization(t *testing.T) {
	// Test that realm is normalized to uppercase
	config := auth_providers.NewKerberosAuthenticatorBuilder().
		WithRealm("example.com")

	serverConfig := config.GetServerConfig()
	if serverConfig.KerberosRealm != "EXAMPLE.COM" {
		t.Errorf("expected realm to be uppercase 'EXAMPLE.COM', got '%s'", serverConfig.KerberosRealm)
	}
}

func TestCommandAuthConfigKerberos_GetHttpClient(t *testing.T) {
	// Skip test if TEST_KEYFACTOR_KRB_AUTH is not set
	if os.Getenv("TEST_KEYFACTOR_KRB_AUTH") != "1" && os.Getenv("TEST_KEYFACTOR_KRB_AUTH") != "true" {
		t.Skip("Skipping TestCommandAuthConfigKerberos_GetHttpClient - set TEST_KEYFACTOR_KRB_AUTH=true to run")
		return
	}

	config := &auth_providers.CommandAuthConfigKerberos{
		Username:   os.Getenv(auth_providers.EnvKeyfactorKrbUsername),
		Password:   os.Getenv(auth_providers.EnvKeyfactorKrbPassword),
		Realm:      os.Getenv(auth_providers.EnvKeyfactorKrbRealm),
		ConfigPath: os.Getenv(auth_providers.EnvKeyfactorKrbConfig),
	}

	client, err := config.GetHttpClient()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if client == nil {
		t.Fatalf("expected a non-nil http.Client")
	}
}

func TestCommandAuthConfigKerberos_Authenticate(t *testing.T) {
	// Skip test if TEST_KEYFACTOR_KRB_AUTH is not set
	if os.Getenv("TEST_KEYFACTOR_KRB_AUTH") != "1" && os.Getenv("TEST_KEYFACTOR_KRB_AUTH") != "true" {
		t.Skip("Skipping TestCommandAuthConfigKerberos_Authenticate - set TEST_KEYFACTOR_KRB_AUTH=true to run")
		return
	}

	t.Log("Testing Kerberos Auth with Environmental variables")
	noParamsConfig := &auth_providers.CommandAuthConfigKerberos{}
	authKerberosTest(t, "with complete Environmental variables", false, noParamsConfig)

	t.Log("Testing Kerberos Auth with invalid config file path")
	invFilePath := &auth_providers.CommandAuthConfigKerberos{}
	invFilePath.WithConfigFile("invalid-file-path")
	invalidPathExpectedError := []string{"no such file or directory", "invalid-file-path"}
	authKerberosTest(t, "with invalid config file PATH", true, invFilePath, invalidPathExpectedError...)

	// Environment variables are not set
	t.Log("Unsetting environment variables")
	username, password, realm, keytab, configPath, ccache := exportKerberosEnvVariables()
	unsetKerberosEnvVariables()
	defer func() {
		t.Log("Resetting environment variables")
		setKerberosEnvVariables(username, password, realm, keytab, configPath, ccache)
	}()

	t.Log("Testing Kerberos Auth with no Environmental variables")
	incompleteEnvConfig := &auth_providers.CommandAuthConfigKerberos{}
	incompleteEnvConfigExpectedError := "Kerberos authentication requires one of"
	authKerberosTest(
		t,
		"with incomplete Environmental variables",
		true,
		incompleteEnvConfig,
		incompleteEnvConfigExpectedError,
	)

	t.Log("Testing auth with only username")
	usernameOnlyConfig := &auth_providers.CommandAuthConfigKerberos{
		Username: "test-username",
	}
	usernameOnlyConfigExpectedError := "password or environment variable"
	authKerberosTest(t, "username only", true, usernameOnlyConfig, usernameOnlyConfigExpectedError)

	t.Log("Testing auth with username and password but no realm")
	noRealmConfig := &auth_providers.CommandAuthConfigKerberos{
		Username: "test-username",
		Password: "test-password",
	}
	noRealmExpectedError := "Kerberos realm or environment variable"
	authKerberosTest(t, "no realm", true, noRealmConfig, noRealmExpectedError)

	t.Log("Testing auth w/ full params variables")
	fullParamsConfig := &auth_providers.CommandAuthConfigKerberos{
		Username:   username,
		Password:   password,
		Realm:      realm,
		ConfigPath: configPath,
	}
	authKerberosTest(t, "w/ full params variables", false, fullParamsConfig)

	t.Log("Testing auth w/ invalid password")
	fullParamsInvalidPassConfig := &auth_providers.CommandAuthConfigKerberos{
		Username:   username,
		Password:   "invalid-password",
		Realm:      realm,
		ConfigPath: configPath,
	}
	invalidCredsExpectedError := []string{"failed to login", "Kerberos"}
	authKerberosTest(t, "w/ invalid password", true, fullParamsInvalidPassConfig, invalidCredsExpectedError...)

	t.Log("Testing auth w/ username@realm format")
	usernameRealmConfig := &auth_providers.CommandAuthConfigKerberos{
		Username:   fmt.Sprintf("%s@%s", username, realm),
		Password:   password,
		ConfigPath: configPath,
	}
	authKerberosTest(t, "w/ username@realm format", false, usernameRealmConfig)
}

func TestCommandAuthConfigKerberos_Build(t *testing.T) {
	// Skip test if TEST_KEYFACTOR_KRB_AUTH is not set
	if os.Getenv("TEST_KEYFACTOR_KRB_AUTH") != "1" && os.Getenv("TEST_KEYFACTOR_KRB_AUTH") != "true" {
		t.Skip("Skipping TestCommandAuthConfigKerberos_Build - set TEST_KEYFACTOR_KRB_AUTH=true to run")
		return
	}

	config := &auth_providers.CommandAuthConfigKerberos{
		Username:   os.Getenv(auth_providers.EnvKeyfactorKrbUsername),
		Password:   os.Getenv(auth_providers.EnvKeyfactorKrbPassword),
		Realm:      os.Getenv(auth_providers.EnvKeyfactorKrbRealm),
		ConfigPath: os.Getenv(auth_providers.EnvKeyfactorKrbConfig),
	}

	authenticator, err := config.Build()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if authenticator == nil {
		t.Fatalf("expected a non-nil Authenticator")
	}
}

// setKerberosEnvVariables sets the Kerberos environment variables
func setKerberosEnvVariables(username, password, realm, keytab, configPath, ccache string) {
	os.Setenv(auth_providers.EnvKeyfactorKrbUsername, username)
	os.Setenv(auth_providers.EnvKeyfactorKrbPassword, password)
	os.Setenv(auth_providers.EnvKeyfactorKrbRealm, realm)
	os.Setenv(auth_providers.EnvKeyfactorKrbKeytab, keytab)
	os.Setenv(auth_providers.EnvKeyfactorKrbConfig, configPath)
	os.Setenv(auth_providers.EnvKeyfactorKrbCCache, ccache)
}

// exportKerberosEnvVariables exports the Kerberos environment variables
func exportKerberosEnvVariables() (string, string, string, string, string, string) {
	username := os.Getenv(auth_providers.EnvKeyfactorKrbUsername)
	password := os.Getenv(auth_providers.EnvKeyfactorKrbPassword)
	realm := os.Getenv(auth_providers.EnvKeyfactorKrbRealm)
	keytab := os.Getenv(auth_providers.EnvKeyfactorKrbKeytab)
	configPath := os.Getenv(auth_providers.EnvKeyfactorKrbConfig)
	ccache := os.Getenv(auth_providers.EnvKeyfactorKrbCCache)
	return username, password, realm, keytab, configPath, ccache
}

// unsetKerberosEnvVariables unsets the Kerberos environment variables
func unsetKerberosEnvVariables() {
	os.Unsetenv(auth_providers.EnvKeyfactorKrbUsername)
	os.Unsetenv(auth_providers.EnvKeyfactorKrbPassword)
	os.Unsetenv(auth_providers.EnvKeyfactorKrbRealm)
	os.Unsetenv(auth_providers.EnvKeyfactorKrbKeytab)
	os.Unsetenv(auth_providers.EnvKeyfactorKrbConfig)
	os.Unsetenv(auth_providers.EnvKeyfactorKrbCCache)
}

func authKerberosTest(
	t *testing.T, testName string, allowFail bool, config *auth_providers.CommandAuthConfigKerberos,
	errorContains ...string,
) {
	t.Run(
		fmt.Sprintf("Kerberos Auth Test %s", testName), func(t *testing.T) {

			err := config.Authenticate()
			if allowFail {
				if err == nil {
					t.Errorf("Kerberos auth test '%s' should have failed", testName)
					t.FailNow()
					return
				}
				if len(errorContains) > 0 {
					for _, ec := range errorContains {
						if !strings.Contains(err.Error(), ec) {
							t.Errorf("Kerberos auth test '%s' failed with unexpected error %v", testName, err)
							t.FailNow()
							return
						}
					}
				}
				t.Logf("Kerberos auth test '%s' failed as expected with %v", testName, err)
				return
			}
			if err != nil {
				t.Errorf("Kerberos auth test '%s' failed with %v", testName, err)
				t.FailNow()
				return
			}
		},
	)
}
