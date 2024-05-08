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

package active_directory

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"keyfactor_auth_client/auth_providers"
)

const (
	EnvKeyfactorDomain   = "KEYFACTOR_DOMAIN"
	EnvKeyfactorUsername = "KEYFACTOR_USERNAME"
	EnvKeyfactorPassword = "KEYFACTOR_PASSWORD"
)

// CommandAuthConfigActiveDirectory represents the configuration needed for Active Directory authentication.
// It embeds CommandAuthConfigBasic and adds additional fields specific to Active Directory.
type CommandAuthConfigActiveDirectory struct {
	// CommandAuthConfig is a reference to the base configuration needed for authentication to Keyfactor Command API
	auth_providers.CommandAuthConfigBasic

	// Domain is the domain of the Active Directory used to authenticate to Keyfactor Command API
	Domain string `json:"domain"`
}

// Authenticate performs the authentication process for Active Directory.
// It validates the authentication configuration, generates the authentication header, and calls the basic authentication method.
func (c *CommandAuthConfigActiveDirectory) Authenticate() error {
	cErr := c.ValidateAuthConfig()
	if cErr != nil {
		return cErr
	}

	c.AuthHeader = fmt.Sprintf("Basic %s", c.getBasicAuthHeader())

	aErr := c.CommandAuthConfigBasic.Authenticate()
	if aErr != nil {
		return aErr
	}

	return nil
}

// getBasicAuthHeader generates the basic authentication header value.
// It combines the username, domain, and password with a colon separator, and encodes the resulting string in base64.
func (c *CommandAuthConfigActiveDirectory) getBasicAuthHeader() string {
	authStr := fmt.Sprintf("%s@%s:%s", c.Username, c.Domain, c.Password)
	return base64.StdEncoding.EncodeToString([]byte(authStr))
}

// parseUsernameDomain parses the username to extract the domain if it's included in the username.
// It supports two formats: "username@domain" and "domain\username".
func (c *CommandAuthConfigActiveDirectory) parseUsernameDomain() error {
	domainErr := fmt.Errorf("domain or environment variable %s is required", EnvKeyfactorDomain)
	if strings.Contains(c.Username, "@") {
		dSplit := strings.Split(c.Username, "@")
		if len(dSplit) != 2 {
			return domainErr
		}
		c.Username = dSplit[0] // remove domain from username
		c.Domain = dSplit[1]
	} else if strings.Contains(c.Username, "\\") {
		dSplit := strings.Split(c.Username, "\\")
		if len(dSplit) != 2 {
			return domainErr
		}
		c.Domain = dSplit[0]
		c.Username = dSplit[1] // remove domain from username
	}

	return nil
}

// ValidateAuthConfig validates the authentication configuration for Active Directory.
// It checks the username, domain, and password, and retrieves them from environment variables if they're not set.
func (c *CommandAuthConfigActiveDirectory) ValidateAuthConfig() error {
	cErr := c.CommandAuthConfigBasic.ValidateAuthConfig()
	if cErr != nil {
		return cErr
	}

	if c.Username == "" {
		if username, ok := os.LookupEnv(EnvKeyfactorUsername); ok {
			c.Username = username
		} else {
			return fmt.Errorf("username or environment variable %s is required", EnvKeyfactorUsername)
		}
	}

	domainErr := c.parseUsernameDomain()
	if domainErr != nil {
		return domainErr

	}

	if c.Password == "" {
		if password, ok := os.LookupEnv(EnvKeyfactorPassword); ok {
			c.Password = password
		} else {
			return fmt.Errorf("password or environment variable %s is required", EnvKeyfactorPassword)
		}
	}

	if c.Domain == "" {
		if domain, ok := os.LookupEnv(EnvKeyfactorDomain); ok {
			c.Domain = domain
		} else {
			return domainErr
		}
	}

	return nil
}
