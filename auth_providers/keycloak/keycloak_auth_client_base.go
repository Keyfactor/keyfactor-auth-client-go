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

package keycloak

import (
	"os"

	"keyfactor_auth_client/auth_providers"
)

const (
	EnvKeyfactorAuthHostname = "KEYFACTOR_AUTH_HOST_NAME"
	EnvKeyfactorAuthPort     = "KEYFACTOR_AUTH_PORT"
)

type CommandAuthConfigKeyCloak struct {
	// CommandAuthConfig is a reference to the base configuration needed for authentication to Keyfactor Command API
	auth_providers.CommandAuthConfig

	// AuthHostName is the hostname of the Keycloak server
	AuthHostName string `json:"auth_host_name"`

	// AuthPort is the port of the Keycloak server
	AuthPort string `json:"auth_port"`

	// AuthType is the type of Keycloak auth to use such as client_credentials, password, etc.
	AuthType string `json:"auth_type"`
}

// ValidateAuthConfig validates the authentication configuration for Keycloak.
func (c *CommandAuthConfigKeyCloak) ValidateAuthConfig() error {
	pErr := c.CommandAuthConfig.ValidateAuthConfig()
	if pErr != nil {
		return pErr
	}

	if c.AuthHostName == "" {
		if authHostName, ok := os.LookupEnv(EnvKeyfactorAuthHostname); ok {
			c.AuthHostName = authHostName
		} else {
			c.AuthHostName = c.CommandHostName
		}
	}
	if c.AuthPort == "" {
		if port, ok := os.LookupEnv(EnvKeyfactorAuthPort); ok {
			c.AuthPort = port
		} else {
			c.AuthPort = DefaultKeyfactorAuthPort
		}
	}
	return nil
}
