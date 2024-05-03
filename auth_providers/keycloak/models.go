package keycloak

import (
	"os"
	"time"

	"keyfactor_auth/auth_providers"
)

const (
	EnvKeyfactorAuthHostname = "KEYFACTOR_AUTH_HOST_NAME"
	EnvKeyfactorAuthPort     = "KEYFACTOR_AUTH_PORT"
	EnvKeyfactorAccessToken  = "KEYFACTOR_ACCESS_TOKEN"
)

type CommandAuthConfigKeyCloak struct {
	auth_providers.CommandAuthConfig
	AuthHostName string `json:"auth_host_name"`
	AuthPort     string `json:"auth_port"`
	AuthType     string `json:"auth_type"` // The type of Keycloak auth to use such as client_credentials, password, etc.
}

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

type CommandAuthKeyCloakClientCredentials struct {
	CommandAuthConfigKeyCloak
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
	Realm        string    `json:"realm"`
	TokenURL     string    `json:"token_url"`
}
