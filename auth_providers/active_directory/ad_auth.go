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
)

func (c *CommandAuthConfigActiveDirectory) Authenticate() error {
	cErr := c.ValidateAuthConfig()
	if cErr != nil {
		return cErr
	}

	c.AuthHeader = fmt.Sprintf("Basic %s", c.getBasicAuthHeader())
	return nil
}

func (c *CommandAuthConfigActiveDirectory) getBasicAuthHeader() string {
	authStr := fmt.Sprintf("%s@%s:%s", c.Domain, c.Username, c.Password)
	return base64.StdEncoding.EncodeToString([]byte(authStr))
}

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

	if c.Password == "" {
		if password, ok := os.LookupEnv(EnvKeyfactorPassword); ok {
			c.Password = password
		} else {
			return fmt.Errorf("password or environment variable KEYFACTOR_PASSWORD is required")
		}
	}

	if c.Domain == "" {
		if domain, ok := os.LookupEnv("KEYFACTOR_DOMAIN"); ok {
			c.Domain = domain
		} else {
			//check if domain is in username with @ or \\
			if strings.Contains(c.Username, "@") {
				domain := strings.Split(c.Username, "@")
				if len(domain) != 2 {
					return fmt.Errorf("domain or environment variable %s is required", EnvKeyfactorDomain)
				}
				c.Username = domain[0] // remove domain from username
				c.Domain = domain[1]
			} else if strings.Contains(c.Username, "\\") {
				domain := strings.Split(c.Username, "\\")
				if len(domain) != 2 {
					return fmt.Errorf("domain or environment variable %s is required", EnvKeyfactorDomain)
				}
				c.Domain = domain[0]
				c.Username = domain[1] // remove domain from username
			} else {
				return fmt.Errorf("domain or environment variable %s is required", EnvKeyfactorDomain)
			}
		}
	}
	return nil
}

func (c *CommandAuthConfigActiveDirectory) GetAuthHeader() string {
	return c.AuthHeader
}
