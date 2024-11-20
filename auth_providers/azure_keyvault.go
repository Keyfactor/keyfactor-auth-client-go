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

package auth_providers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

const (
	EnvAzureVaultName  = "AZURE_KEYVAULT_NAME"
	EnvAzureSecretName = "AZURE_SECRET_NAME"
)

// ConfigProviderAzureKeyVault is an Authenticator that uses Azure Key Vault for authentication.
type ConfigProviderAzureKeyVault struct {
	SecretName        string `json:"secret_name,omitempty" yaml:"secret_name,omitempty"`
	VaultName         string `json:"vault_name,omitempty" yaml:"vault_name,omitempty"`
	DefaultCredential *azidentity.DefaultAzureCredential
	CommandConfig     *Config
	//TenantID       string `json:"tenant_id;omitempty"`
	//SubscriptionID string `json:"subscription_id;omitempty"`
	//ResourceGroup  string `json:"resource_group;omitempty"`
}

// NewConfigProviderAzureKeyVault creates a new instance of ConfigProviderAzureKeyVault.
func NewConfigProviderAzureKeyVault() *ConfigProviderAzureKeyVault {
	return &ConfigProviderAzureKeyVault{}
}

// String returns a string representation of the ConfigProviderAzureKeyVault.
func (a *ConfigProviderAzureKeyVault) String() string {
	return fmt.Sprintf("SecretName: %s, AzureVaultName: %s", a.SecretName, a.VaultName)
}

// WithSecretName sets the secret name for authentication.
func (a *ConfigProviderAzureKeyVault) WithSecretName(secretName string) *ConfigProviderAzureKeyVault {
	a.SecretName = secretName
	return a
}

// WithVaultName sets the vault name for authentication.
func (a *ConfigProviderAzureKeyVault) WithVaultName(vaultName string) *ConfigProviderAzureKeyVault {
	a.VaultName = vaultName
	return a
}

// Authenticate authenticates to Azure.
func (a *ConfigProviderAzureKeyVault) Authenticate() error {

	vErr := a.Validate()
	if vErr != nil {
		return vErr
	}

	// Create a context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), DefaultClientTimeout*time.Second)
	defer cancel()

	// Add custom metadata to context
	ctx = context.WithValue(ctx, contextKey("operation"), "AzureAuthenticate")

	// Try to authenticate using DefaultAzureCredential
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to obtain a credential: %w", err)
	}
	a.DefaultCredential = cred
	return nil
}

// Validate validates the ConfigProviderAzureKeyVault.
func (a *ConfigProviderAzureKeyVault) Validate() error {
	if a.SecretName == "" {
		// Check if the secret name is set in the environment
		if secretName := os.Getenv(EnvAzureSecretName); secretName != "" {
			a.SecretName = secretName
		} else {
			return fmt.Errorf("Azure KeyVault `SecretName` is required")
		}
	}
	if a.VaultName == "" {
		// Check if the vault name is set in the environment
		if vaultName := os.Getenv(EnvAzureVaultName); vaultName != "" {
			a.VaultName = vaultName
		} else {
			return fmt.Errorf("Azure KeyVault `VaultName` is required")
		}
	}
	return nil
}

// LoadConfigFromAzureKeyVault loads a Config type from Azure Key Vault.
func (a *ConfigProviderAzureKeyVault) LoadConfigFromAzureKeyVault() (*Config, error) {
	if a.DefaultCredential == nil {
		aErr := a.Authenticate()
		if aErr != nil {
			return nil, aErr
		}
	}

	// Create a context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), DefaultClientTimeout*time.Second)
	defer cancel()

	// Add custom metadata to context
	ctx = context.WithValue(ctx, contextKey("operation"), "LoadConfigFromAzureKeyVault")
	ctx = context.WithValue(ctx, contextKey("vaultName"), a.VaultName)
	ctx = context.WithValue(ctx, contextKey("secretName"), a.SecretName)
	// Create a client to access the Azure Key Vault
	vaultURL := fmt.Sprintf("https://%s.vault.azure.net/", a.VaultName)
	client, cErr := azsecrets.NewClient(vaultURL, a.DefaultCredential, nil)
	if cErr != nil {
		return nil, cErr
	}

	// Retrieve the secret from the Azure Key Vault
	secretResp, sErr := client.GetSecret(ctx, a.SecretName, "", nil)
	if sErr != nil {
		return nil, sErr
	}

	// Check if the secret value is nil to avoid dereferencing a nil pointer
	if secretResp.Value == nil {
		return nil, fmt.Errorf("secret value for '%s' in vault '%s' is nil", a.SecretName, a.VaultName)
	}

	// Parse the secret value into a Config type
	var config Config
	if jErr := json.Unmarshal([]byte(*secretResp.Value), &config); jErr != nil {
		//attempt to unmarshal as a single server config
		var singleServerConfig Server
		if sjErr := json.Unmarshal([]byte(*secretResp.Value), &singleServerConfig); sjErr == nil {
			config.Servers = make(map[string]Server)
			config.Servers[DefaultConfigProfile] = singleServerConfig
		} else {
			return nil, jErr
		}
	}

	a.CommandConfig = &config
	return &config, nil
}

// Example usage of ConfigProviderAzureKeyVault
//
// This example demonstrates how to use ConfigProviderAzureKeyVault to load a configuration from Azure Key Vault.
//
//	func ExampleConfigProviderAzureKeyVault() {
//		provider := NewConfigProviderAzureKeyVault().
//			WithSecretName("my-secret").
//			WithVaultName("my-vault")
//
//		err := provider.Authenticate()
//		if err != nil {
//			fmt.Println("Failed to authenticate:", err)
//			return
//		}
//
//		config, err := provider.LoadConfigFromAzureKeyVault()
//		if err != nil {
//			fmt.Println("Failed to load config from Azure Key Vault:", err)
//			return
//		}
//
//		fmt.Println("Loaded config from Azure Key Vault:", config)
//	}
