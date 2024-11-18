package auth_providers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/stretchr/testify/assert"
)

func TestConfigProviderAzureKeyVault_Authenticate(t *testing.T) {
	if isRunningInGithubAction() {
		t.Skip("Testing via Github Actions not supported, skipping test")
	}
	provider := auth_providers.NewConfigProviderAzureKeyVault()
	err := provider.Authenticate()
	assert.NoError(t, err, "expected no error during authentication")
}

func TestConfigProviderAzureKeyVault_LoadConfigFromAzureKeyVault(t *testing.T) {
	if isRunningInGithubAction() {
		t.Skip("Testing via Github Actions not supported, skipping test")
	}
	vaultName := os.Getenv(auth_providers.EnvAzureVaultName)
	secretName := os.Getenv(auth_providers.EnvAzureSecretName)

	t.Logf("vaultName: %s, secretName: %s", vaultName, secretName)

	// Test with environment variables set
	t.Logf("Testing with only environment variables set")
	envConf := auth_providers.NewConfigProviderAzureKeyVault()
	envConfig, cErr := envConf.LoadConfigFromAzureKeyVault()
	assert.NoError(t, cErr, "expected no error during config load")
	assert.NotNil(t, envConfig, "expected config to be loaded")

	// Test with mixed environment variables and parameters set
	t.Logf("Testing with mixed environment variables and parameters set")
	os.Unsetenv(auth_providers.EnvAzureSecretName)
	envParamsSecretName := auth_providers.NewConfigProviderAzureKeyVault().
		WithSecretName(secretName)
	envParamsSecretNameConfig, envParamsSecretNameErr := envParamsSecretName.LoadConfigFromAzureKeyVault()
	assert.NoError(t, envParamsSecretNameErr, "expected no error during config load")
	assert.NotNil(t, envParamsSecretNameConfig, "expected config to be loaded")
	os.Setenv(auth_providers.EnvAzureSecretName, secretName)

	// Test with mixed environment variables and parameters set
	t.Logf("Testing with mixed environment variables and parameters set")
	os.Unsetenv(auth_providers.EnvAzureVaultName)
	envParamsVaultName := auth_providers.NewConfigProviderAzureKeyVault().
		WithVaultName(vaultName)
	envParamsVaultNameConfig, envParamsVaultNameErr := envParamsVaultName.LoadConfigFromAzureKeyVault()
	assert.NoError(t, envParamsVaultNameErr, "expected no error during config load")
	assert.NotNil(t, envParamsVaultNameConfig, "expected config to be loaded")
	os.Setenv(auth_providers.EnvAzureVaultName, vaultName)

	// Test with no environment variables set
	t.Logf("Testing with no environment variables set")
	unsetAkvEnvVars()
	fullParams := auth_providers.NewConfigProviderAzureKeyVault().
		WithSecretName(secretName).
		WithVaultName(vaultName)
	fullParamsConfig, fullParamsErr := fullParams.LoadConfigFromAzureKeyVault()
	assert.NoError(t, fullParamsErr, "expected no error during config load")
	assert.NotNil(t, fullParamsConfig, "expected config to be loaded")
}

func TestConfigProviderAzureKeyVault_Validate(t *testing.T) {
	provider := auth_providers.NewConfigProviderAzureKeyVault().
		WithSecretName("my-secret").
		WithVaultName("my-vault")

	err := provider.Validate()
	assert.NoError(t, err, "expected no error during validation")
}

func unsetAkvEnvVars() {
	os.Unsetenv(auth_providers.EnvAzureSecretName)
	os.Unsetenv(auth_providers.EnvAzureVaultName)
}

func isRunningOnAzureByEnvVar() bool {
	_, exists := os.LookupEnv("AZURE_REGION")
	return exists
}

func isRunningOnAzureByIMDS() bool {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest("GET", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

func isRunningOnAzureByAgent() bool {
	_, err := os.Stat("/usr/sbin/waagent")
	return err == nil
}

func hasManagedIdentity() (bool, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest("GET", "http://169.254.169.254/metadata/identity?api-version=2021-02-01", nil)
	if err != nil {
		return false, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("error making request to IMDS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil // No managed identity attached
	}

	var identityMetadata map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&identityMetadata); err != nil {
		return false, fmt.Errorf("error decoding identity metadata: %w", err)
	}

	// Check for the presence of identity-related fields
	if _, exists := identityMetadata["compute"]; exists {
		return true, nil
	}
	return false, nil
}

func isRunningInGithubAction() bool {
	_, exists := os.LookupEnv("GITHUB_RUN_ID")
	return exists
}
