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
