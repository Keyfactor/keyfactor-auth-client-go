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
	"encoding/json"
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

// TestCommandAuthConfigKerberos_GetServerConfig_DoesNotPersistSynthesizedDefault
// is the CommandAuthConfigKerberos analogue of
// TestCommandAuthConfig_GetServerConfig_DoesNotPersistSynthesizedDefault in
// auth_core_test.go. CommandAuthConfigKerberos defines its own
// GetServerConfig() that shadows the embedded CommandAuthConfig's method via
// Go's method resolution, so a fix landed only on the base type does not
// protect this -- or any other real caller-facing -- concrete type.
//
// This exercises only the embedded CommandAuthConfig.ValidateAuthConfig(),
// not CommandAuthConfigKerberos.ValidateAuthConfig(), which requires a real
// krb5.conf file/ticket cache on disk and is irrelevant to this bug: the
// clientTimeoutDefaulted flag being tested is set by the embedded method
// regardless of which concrete type wraps it.
func TestCommandAuthConfigKerberos_GetServerConfig_DoesNotPersistSynthesizedDefault(t *testing.T) {
	config := &auth_providers.CommandAuthConfigKerberos{
		CommandAuthConfig: auth_providers.CommandAuthConfig{
			CommandHostName: "test-host",
			CommandPort:     443,
			CommandAPIPath:  "KeyfactorAPI",
		},
	}

	if err := config.CommandAuthConfig.ValidateAuthConfig(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	server := config.GetServerConfig()
	if server.ClientTimeout != 0 {
		t.Fatalf("expected Server.ClientTimeout to be omitted (0) for a synthesized default, got %d", server.ClientTimeout)
	}
}

// TestCommandAuthConfigKerberos_GetServerConfig_PersistsExplicitTimeout proves
// the companion positive case: an explicitly configured timeout must still be
// serialized by CommandAuthConfigKerberos.GetServerConfig().
func TestCommandAuthConfigKerberos_GetServerConfig_PersistsExplicitTimeout(t *testing.T) {
	config := &auth_providers.CommandAuthConfigKerberos{
		CommandAuthConfig: auth_providers.CommandAuthConfig{
			CommandHostName: "test-host",
			CommandPort:     443,
			CommandAPIPath:  "KeyfactorAPI",
		},
	}
	config.WithClientTimeout(300)

	if err := config.CommandAuthConfig.ValidateAuthConfig(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	server := config.GetServerConfig()
	if server.ClientTimeout != 300 {
		t.Fatalf("expected Server.ClientTimeout to be 300, got %d", server.ClientTimeout)
	}
}

// TestCommandAuthConfigKerberos_PersistedDefaultConfigFile_DoesNotShadowEnvVar
// is the CommandAuthConfigKerberos analogue of
// TestCommandAuthConfig_PersistedDefaultConfigFile_DoesNotShadowEnvVar: a
// synthesized default persisted to a config file by a first run must not
// shadow KEYFACTOR_CLIENT_TIMEOUT on a second run that loads that file.
func TestCommandAuthConfigKerberos_PersistedDefaultConfigFile_DoesNotShadowEnvVar(t *testing.T) {
	// Run 1: nothing explicitly configured for client timeout.
	run1 := &auth_providers.CommandAuthConfigKerberos{
		CommandAuthConfig: auth_providers.CommandAuthConfig{
			CommandHostName: "test-host",
			CommandPort:     443,
			CommandAPIPath:  "KeyfactorAPI",
		},
	}
	if err := run1.CommandAuthConfig.ValidateAuthConfig(); err != nil {
		t.Fatalf("run1: expected no error, got %v", err)
	}

	persisted := run1.GetServerConfig()

	// Persist exactly what kfutil's login flow persists: the resolved Server
	// config, verbatim, to the "default" profile of a config file.
	dir := t.TempDir()
	path := dir + "/command_config.json"
	fileContents, mErr := json.Marshal(
		map[string]interface{}{
			"servers": map[string]interface{}{
				"default": persisted,
			},
		},
	)
	if mErr != nil {
		t.Fatalf("failed to marshal persisted config: %v", mErr)
	}
	if err := os.WriteFile(path, fileContents, 0o600); err != nil {
		t.Fatalf("failed to write persisted config file: %v", err)
	}

	// Run 2: a fresh process loads that persisted file and has
	// KEYFACTOR_CLIENT_TIMEOUT set in its environment.
	t.Setenv(auth_providers.EnvKeyfactorClientTimeout, "1800")

	run2 := &auth_providers.CommandAuthConfigKerberos{}
	run2.WithConfigFile(path).WithConfigProfile("default")

	if _, err := run2.CommandAuthConfig.LoadConfig(run2.ConfigProfile, run2.ConfigFilePath, true); err != nil {
		t.Fatalf("run2: expected no error from LoadConfig, got %v", err)
	}

	if err := run2.CommandAuthConfig.ValidateAuthConfig(); err != nil {
		t.Fatalf("run2: expected no error from ValidateAuthConfig, got %v", err)
	}

	if run2.HttpClientTimeout != 1800 {
		t.Fatalf(
			"expected KEYFACTOR_CLIENT_TIMEOUT=1800 to be honored, but a persisted synthesized default shadowed it: got HttpClientTimeout=%d",
			run2.HttpClientTimeout,
		)
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
