package auth_providers_test

import (
	"os"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/stretchr/testify/assert"
)

func TestConfigProviderAzureKeyVault_Authenticate(t *testing.T) {
	provider := auth_providers.NewConfigProviderAzureKeyVault()
	err := provider.Authenticate()
	assert.NoError(t, err, "expected no error during authentication")
}

func TestConfigProviderAzureKeyVault_LoadConfigFromAzureKeyVault(t *testing.T) {
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
