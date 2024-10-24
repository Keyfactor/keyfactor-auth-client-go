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
	"encoding/json"
	"os"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"gopkg.in/yaml.v2"
)

func TestReadServerFromJSON(t *testing.T) {
	filePath := "test_config.json"
	server := &auth_providers.Server{
		Host:          "localhost",
		Port:          8080,
		OAuthTokenUrl: "https://auth.localhost:8443/openid/token",
		Username:      "user",
		Password:      "pass",
		ClientID:      "client_id",
		ClientSecret:  "client_secret",
		Domain:        "domain",
		APIPath:       "api",
	}

	err := auth_providers.WriteServerToJSON(filePath, server)
	if err != nil {
		t.Fatalf("failed to write server to JSON: %v", err)
	}
	defer os.Remove(filePath)

	readServer, err := auth_providers.ReadServerFromJSON(filePath)
	if err != nil {
		t.Fatalf("failed to read server from JSON: %v", err)
	}

	if !compareServers(readServer, server) {
		t.Fatalf("expected %v, got %v", server, readServer)
	}
}

func TestWriteServerToJSON(t *testing.T) {
	filePath := "test_server.json"
	server := &auth_providers.Server{
		Host:          "localhost",
		Port:          8080,
		OAuthTokenUrl: "https://auth.localhost:8443/openid/token",
		Username:      "user",
		Password:      "pass",
		ClientID:      "client_id",
		ClientSecret:  "client_secret",
		Domain:        "domain",
		APIPath:       "api",
	}

	err := auth_providers.WriteServerToJSON(filePath, server)
	if err != nil {
		t.Fatalf("failed to write server to JSON: %v", err)
	}
	defer os.Remove(filePath)

	file, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	var readServer auth_providers.Server
	err = json.Unmarshal(file, &readServer)
	if err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if !compareServers(&readServer, server) {
		t.Fatalf("expected %v, got %v", server, readServer)
	}
}

func TestReadServerFromYAML(t *testing.T) {
	filePath := "test_server.yaml"
	server := &auth_providers.Server{
		Host:          "localhost",
		Port:          8080,
		OAuthTokenUrl: "https://auth.localhost:8443/openid/token",
		Username:      "user",
		Password:      "pass",
		ClientID:      "client_id",
		ClientSecret:  "client_secret",
		Domain:        "domain",
		APIPath:       "api",
	}

	err := auth_providers.WriteServerToYAML(filePath, server)
	if err != nil {
		t.Fatalf("failed to write server to YAML: %v", err)
	}
	defer os.Remove(filePath)

	readServer, err := auth_providers.ReadServerFromYAML(filePath)
	if err != nil {
		t.Fatalf("failed to read server from YAML: %v", err)
	}

	if !compareServers(readServer, server) {
		t.Fatalf("expected %v, got %v", server, readServer)
	}
}

func TestWriteServerToYAML(t *testing.T) {
	filePath := "test_server.yaml"
	server := &auth_providers.Server{
		Host:          "localhost",
		Port:          8080,
		OAuthTokenUrl: "https://auth.localhost:8443/openid/token",
		Username:      "user",
		Password:      "pass",
		ClientID:      "client_id",
		ClientSecret:  "client_secret",
		Domain:        "domain",
		APIPath:       "api",
	}

	err := auth_providers.WriteServerToYAML(filePath, server)
	if err != nil {
		t.Fatalf("failed to write server to YAML: %v", err)
	}
	defer os.Remove(filePath)

	file, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	var readServer auth_providers.Server
	err = yaml.Unmarshal(file, &readServer)
	if err != nil {
		t.Fatalf("failed to unmarshal YAML: %v", err)
	}

	if !compareServers(&readServer, server) {
		t.Fatalf("expected %v, got %v", server, readServer)
	}
}

func TestMergeConfigFromFile(t *testing.T) {
	filePath := "test_config.json"
	config := &auth_providers.Config{
		Servers: map[string]auth_providers.Server{
			"server1": {
				Host: "localhost",
				Port: 8080,
			},
		},
	}

	err := auth_providers.WriteConfigToJSON(filePath, config)
	if err != nil {
		t.Fatalf("failed to write config to JSON: %v", err)
	}
	defer os.Remove(filePath)

	newConfig := &auth_providers.Config{
		Servers: map[string]auth_providers.Server{
			"server2": {
				Host: "remotehost",
				Port: 9090,
			},
		},
	}

	err = auth_providers.MergeConfigFromFile(filePath, newConfig)
	if err != nil {
		t.Fatalf("failed to merge config from file: %v", err)
	}

	if len(newConfig.Servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(newConfig.Servers))
	}

	if newConfig.Servers["server1"].Host != "localhost" {
		t.Fatalf("expected server1 host to be localhost, got %s", newConfig.Servers["server1"].Host)
	}

	if newConfig.Servers["server2"].Host != "remotehost" {
		t.Fatalf("expected server2 host to be remotehost, got %s", newConfig.Servers["server2"].Host)
	}
}

func TestReadFullAuthConfigExample(t *testing.T) {
	filePath := "../lib/config/full_auth_config_example.json"
	expectedConfig := &auth_providers.Config{
		Servers: map[string]auth_providers.Server{
			"default": {
				Host:          "keyfactor.command.kfdelivery.com",
				OAuthTokenUrl: "idp.keyfactor.command.kfdelivery.com",
				Username:      "keyfactor",
				Password:      "password",
				ClientID:      "client-id",
				ClientSecret:  "client-secret",
				Domain:        "command",
				APIPath:       "KeyfactorAPI",
				AuthProvider: auth_providers.AuthProvider{
					Type:    "azid",
					Profile: "azure",
					Parameters: map[string]interface{}{
						"secret_name": "command-config-azure",
						"vault_name":  "keyfactor-secrets",
					},
				},
			},
			"server2": {
				Host:          "keyfactor2.command.kfdelivery.com",
				OAuthTokenUrl: "idp.keyfactor2.command.kfdelivery.com",
				Username:      "keyfactor2",
				Password:      "password2",
				ClientID:      "client-id2",
				ClientSecret:  "client-secret2",
				Domain:        "command",
				APIPath:       "KeyfactorAPI",
				AuthProvider: auth_providers.AuthProvider{
					Type:    "azid",
					Profile: "azure",
					Parameters: map[string]interface{}{
						"secret_name": "command-config-azure2",
						"vault_name":  "keyfactor-secrets",
					},
				},
			},
		},
	}

	file, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	var config auth_providers.Config
	err = json.Unmarshal(file, &config)
	if err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if !compareConfigs(&config, expectedConfig) {
		t.Fatalf("expected %v, got %v", expectedConfig, config)
	}
}

func TestReadOAuthConfigExample(t *testing.T) {
	filePath := "../lib/config/oauth_config_example.json"
	expectedConfig := &auth_providers.Config{
		Servers: map[string]auth_providers.Server{
			"default": {
				Host:          "keyfactor.command.kfdelivery.com",
				OAuthTokenUrl: "https://idp.keyfactor.command.kfdelivery.com/oauth2/token",
				ClientID:      "client-id",
				ClientSecret:  "client-secret",
				APIPath:       "KeyfactorAPI",
			},
			"server2": {
				Host:          "keyfactor.command.kfdelivery.com",
				OAuthTokenUrl: "https://idp.keyfactor.command.kfdelivery.com/oauth2/token",
				ClientID:      "client-id",
				ClientSecret:  "client-secret",
				APIPath:       "KeyfactorAPI",
			},
		},
	}

	file, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	var config auth_providers.Config
	err = json.Unmarshal(file, &config)
	if err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if !compareConfigs(&config, expectedConfig) {
		t.Fatalf("expected %v, got %v", expectedConfig, config)
	}
}

func TestReadBasicAuthConfigExample(t *testing.T) {
	filePath := "../lib/config/basic_auth_config_example.json"
	expectedConfig := &auth_providers.Config{
		Servers: map[string]auth_providers.Server{
			"default": {
				Host:     "keyfactor.command.kfdelivery.com",
				Username: "keyfactor",
				Password: "password",
				Domain:   "command",
				APIPath:  "KeyfactorAPI",
			},
			"server2": {
				Host:     "keyfactor2.command.kfdelivery.com",
				Username: "keyfactor2",
				Password: "password2",
				Domain:   "command",
				APIPath:  "Keyfactor/API",
			},
		},
	}

	file, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	var config auth_providers.Config
	err = json.Unmarshal(file, &config)
	if err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if !compareConfigs(&config, expectedConfig) {
		t.Fatalf("expected %v, got %v", expectedConfig, config)
	}
}

func compareConfigs(a, b *auth_providers.Config) bool {
	if len(a.Servers) != len(b.Servers) {
		return false
	}
	for key, serverA := range a.Servers {
		serverB, exists := b.Servers[key]
		if !exists || !compareServers(&serverA, &serverB) {
			return false
		}
	}
	return true
}

func compareServers(a, b *auth_providers.Server) bool {
	return a.Host == b.Host &&
		a.Port == b.Port &&
		a.OAuthTokenUrl == b.OAuthTokenUrl &&
		a.Username == b.Username &&
		a.Password == b.Password &&
		a.ClientID == b.ClientID &&
		a.ClientSecret == b.ClientSecret &&
		a.Domain == b.Domain &&
		a.APIPath == b.APIPath
}
