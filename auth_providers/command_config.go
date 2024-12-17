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
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// Server represents the server configuration for authentication.
type Server struct {
	Host          string       `json:"host,omitempty" yaml:"host,omitempty"`                       // Host is the Command server DNS name or IP address.
	Port          int          `json:"port,omitempty" yaml:"port,omitempty"`                       // Port is the Command server port.
	Username      string       `json:"username,omitempty" yaml:"username,omitempty"`               // Username is the username for authentication.
	Password      string       `json:"password,omitempty" yaml:"password,omitempty"`               // Password is the password for authentication.
	Domain        string       `json:"domain,omitempty" yaml:"domain,omitempty"`                   // Domain is the domain for authentication.
	ClientID      string       `json:"client_id,omitempty" yaml:"client_id,omitempty"`             // ClientID is the client ID for OAuth.
	ClientSecret  string       `json:"client_secret,omitempty" yaml:"client_secret,omitempty"`     // ClientSecret is the client secret for OAuth.
	AccessToken   string       `json:"access_token,omitempty" yaml:"access_token,omitempty"`       // AccessToken is the OAuth access token.
	Scopes        []string     `json:"scopes,omitempty" yaml:"scopes,omitempty"`                   // Scopes is the OAuth scopes.
	Audience      string       `json:"audience,omitempty" yaml:"audience,omitempty"`               // Audience is the OAuth audience.
	OAuthTokenUrl string       `json:"token_url,omitempty" yaml:"token_url,omitempty"`             // OAuthTokenUrl is full URL for OAuth token request endpoint.
	APIPath       string       `json:"api_path,omitempty" yaml:"api_path,omitempty"`               // APIPath is the API path.
	AuthProvider  AuthProvider `json:"auth_provider,omitempty" yaml:"auth_provider,omitempty"`     // AuthProvider contains the authentication provider details.
	SkipTLSVerify bool         `json:"skip_tls_verify,omitempty" yaml:"skip_tls_verify,omitempty"` // TLSVerify determines whether to verify the TLS certificate.
	CACertPath    string       `json:"ca_cert_path,omitempty" yaml:"ca_cert_path,omitempty"`       // CACertPath is the path to the CA certificate to trust.
	AuthType      string       `json:"auth_type,omitempty" yaml:"auth_type,omitempty"`             // AuthType is the type of authentication to use.

}

// AuthProvider represents the authentication provider configuration.
type AuthProvider struct {
	Type       string                 `json:"type,omitempty" yaml:"type,omitempty"`             // Type is the type of authentication provider.
	Profile    string                 `json:"profile,omitempty" yaml:"profile,omitempty"`       // Profile is the profile of the authentication provider.
	Parameters map[string]interface{} `json:"parameters,omitempty" yaml:"parameters,omitempty"` // Parameters are additional parameters for the authentication provider.
}

// Config represents the overall configuration structure.
type Config struct {
	Servers map[string]Server `json:"servers,omitempty" yaml:"servers,omitempty"` // Servers is a map of server configurations.
}

// NewConfig creates a new Config configuration.
func NewConfig() *Config {
	return &Config{
		Servers: make(map[string]Server),
	}
}

// ReadConfigFromJSON reads a Config configuration from a JSON file.
func ReadConfigFromJSON(filePath string) (*Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// ReadConfigFromYAML reads a Config configuration from a YAML file.
func ReadConfigFromYAML(filePath string) (*Config, error) {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(file, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// ReadServerFromJSON reads a Server configuration from a JSON file.
func ReadServerFromJSON(filePath string) (*Server, error) {
	file, fErr := os.Open(filePath)
	if fErr != nil {
		return nil, fErr
	}
	defer file.Close()

	var server Server
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&server); err != nil {
		return nil, err
	}

	return &server, nil
}

// WriteServerToJSON writes a Server configuration to a JSON file.
func WriteServerToJSON(filePath string, server *Server) error {
	file, fErr := os.Create(filePath)
	if fErr != nil {
		return fErr
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(server); err != nil {
		return err
	}

	return nil
}

// ReadServerFromYAML reads a Server configuration from a YAML file.
func ReadServerFromYAML(filePath string) (*Server, error) {
	file, fErr := os.ReadFile(filePath)
	if fErr != nil {
		return nil, fErr
	}

	var server Server
	if err := yaml.Unmarshal(file, &server); err != nil {
		return nil, err
	}

	return &server, nil
}

// WriteServerToYAML writes a Server configuration to a YAML file.
func WriteServerToYAML(filePath string, server *Server) error {
	data, fErr := yaml.Marshal(server)
	if fErr != nil {
		return fErr
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return err
	}

	return nil
}

// WriteConfigToJSON writes a Config configuration to a JSON file.
func WriteConfigToJSON(filePath string, config *Config) error {
	file, fErr := os.Create(filePath)
	if fErr != nil {
		return fErr
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		return err
	}

	return nil
}

// WriteConfigToYAML writes a Config configuration to a YAML file.
func WriteConfigToYAML(filePath string, config *Config) error {
	data, fErr := yaml.Marshal(config)
	if fErr != nil {
		return fErr
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return err
	}

	return nil
}

func (c *Config) Compare(other *Config) bool {
	if len(c.Servers) != len(other.Servers) {
		return false
	}

	for key, server := range c.Servers {
		if otherServer, exists := other.Servers[key]; !exists || !server.Compare(&otherServer) {
			return false
		}
	}

	return true
}

func (s *Server) Compare(other *Server) bool {
	return s.Host == other.Host &&
		s.Port == other.Port &&
		s.Username == other.Username &&
		s.Password == other.Password &&
		s.Domain == other.Domain &&
		s.ClientID == other.ClientID &&
		s.ClientSecret == other.ClientSecret &&
		s.AccessToken == other.AccessToken &&
		s.OAuthTokenUrl == other.OAuthTokenUrl &&
		s.APIPath == other.APIPath &&
		s.SkipTLSVerify == other.SkipTLSVerify &&
		s.CACertPath == other.CACertPath &&
		s.AuthType == other.AuthType
}

// MergeConfigFromFile merges the configuration from a file into the existing Config.
func MergeConfigFromFile(filePath string, config *Config) (*Config, error) {
	// Read the file content
	data, err := os.ReadFile(filePath)
	if err != nil {

		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Determine the file type (JSON or YAML) and unmarshal accordingly
	var tempConfig Config
	if json.Valid(data) {
		if err := json.Unmarshal(data, &tempConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal JSON config: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, &tempConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal YAML config: %w", err)
		}
	}

	// Merge the temporary config into the existing config
	for key, server := range tempConfig.Servers {
		if _, exists := config.Servers[key]; !exists {
			config.Servers[key] = server
		}
	}

	return config, nil
}

// GetAuthType returns the type of authentication to use based on the configuration params.
func (s *Server) GetAuthType() string {
	if (s.ClientID != "" && s.ClientSecret != "") || s.AccessToken != "" {
		s.AuthType = "oauth"
	} else if s.Username != "" && s.Password != "" {
		s.AuthType = "basic"
	} else {
		s.AuthType = ""
	}
	return s.AuthType
}

// GetBasicAuthClientConfig returns the basic auth configuration for the client.
func (s *Server) GetBasicAuthClientConfig() (*CommandAuthConfigBasic, error) {
	configType := s.GetAuthType()
	if configType != "basic" {
		return nil, fmt.Errorf("invalid auth type: %s", configType)
	}

	baseConfig := CommandAuthConfig{}
	baseConfig.
		WithCommandHostName(s.Host).
		WithCommandPort(s.Port).
		WithCommandAPIPath(s.APIPath).
		WithCommandCACert(s.CACertPath).
		WithSkipVerify(s.SkipTLSVerify)

	basicConfig := CommandAuthConfigBasic{
		CommandAuthConfig: baseConfig,
	}
	basicConfig.
		WithUsername(s.Username).
		WithPassword(s.Password).
		WithDomain(s.Domain).
		Build()

	vErr := basicConfig.ValidateAuthConfig()
	if vErr != nil {
		return nil, vErr
	}
	return &basicConfig, nil
}

// GetOAuthClientConfig returns the OAuth configuration for the client.
func (s *Server) GetOAuthClientConfig() (*CommandConfigOauth, error) {
	configType := s.GetAuthType()
	if configType != "oauth" {
		return nil, fmt.Errorf("invalid auth type: %s", configType)
	}
	baseConfig := CommandAuthConfig{}
	baseConfig.
		WithCommandHostName(s.Host).
		WithCommandPort(s.Port).
		WithCommandAPIPath(s.APIPath).
		WithCommandCACert(s.CACertPath).
		WithSkipVerify(s.SkipTLSVerify)

	oauthConfig := CommandConfigOauth{
		CommandAuthConfig: baseConfig,
	}
	oauthConfig.
		WithClientId(s.ClientID).
		WithClientSecret(s.ClientSecret).
		WithAccessToken(s.AccessToken).
		WithTokenUrl(s.OAuthTokenUrl).
		WithScopes(s.Scopes).
		WithAudience(s.Audience).
		Build()

	vErr := oauthConfig.ValidateAuthConfig()
	if vErr != nil {
		return nil, vErr
	}
	return &oauthConfig, nil
}

// Example usage of Config
//
// This example demonstrates how to use Config to read and write server configurations.
//
//	func ExampleConfig_ReadWrite() {
//		config := NewConfig()
//
//		// Add a server configuration
//		config.Servers["exampleServer"] = Server{
//			Host:          "exampleHost",
//			Port:          443,
//			Username:      "exampleUser",
//			Password:      "examplePassword",
//			Domain:        "exampleDomain",
//			ClientID:      "exampleClientID",
//			ClientSecret:  "exampleClientSecret",
//			OAuthTokenUrl: "https://example.com/oauth/token",
//			APIPath:       "/api/v1",
//			SkipTLSVerify: true,
//			CACertPath:    "/path/to/ca-cert.pem",
//			AuthType:      "oauth",
//		}
//
//		// Write the configuration to a JSON file
//		err := WriteConfigToJSON("/path/to/config.json", config)
//		if err != nil {
//			fmt.Println("Failed to write config to JSON:", err)
//		}
//
//		// Read the configuration from a JSON file
//		readConfig, err := ReadConfigFromJSON("/path/to/config.json")
//		if err != nil {
//			fmt.Println("Failed to read config from JSON:", err)
//		} else {
//			fmt.Println("Read config from JSON:", readConfig)
//		}
//
//		// Write the configuration to a YAML file
//		err = WriteConfigToYAML("/path/to/config.yaml", config)
//		if err != nil {
//			fmt.Println("Failed to write config to YAML:", err)
//		}
//
//		// Read the configuration from a YAML file
//		readConfig, err = ReadConfigFromYAML("/path/to/config.yaml")
//		if err != nil {
//			fmt.Println("Failed to read config from YAML:", err)
//		} else {
//			fmt.Println("Read config from YAML:", readConfig)
//		}
//	}
