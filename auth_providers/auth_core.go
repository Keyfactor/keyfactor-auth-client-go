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
	"fmt"
	"os"
)

func (c *CommandAuthConfig) ValidateAuthConfig() error {
	if c.CommandHostName == "" {
		if hostName, ok := os.LookupEnv(EnvKeyfactorHostName); ok {
			c.CommandHostName = hostName
		} else {
			return fmt.Errorf("command_host_name or environment variable %s is required", EnvKeyfactorHostName)
		}
	}
	if c.CommandPort == "" {
		if port, ok := os.LookupEnv(EnvKeyfactorPort); ok {
			c.CommandPort = port
		} else {
			c.CommandPort = DefaultCommandPort
		}
	}
	if c.CommandAPIPath == "" {
		if apiPath, ok := os.LookupEnv(EnvKeyfactorAPIPath); ok {
			c.CommandAPIPath = apiPath
		} else {
			c.CommandAPIPath = DefaultCommandAPIPath
		}
	}
	return nil
}
