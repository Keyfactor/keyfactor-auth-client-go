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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
)

const (
	DefaultKeyfactorAuthRealm = "Keyfactor"
	EnvKeyfactorAuthRealm     = "KEYFACTOR_AUTH_REALM"
)

// CommandAuthKeyCloakClientCredentials represents the configuration needed for Keycloak authentication using client credentials.
// It embeds CommandAuthConfigKeyCloak and adds additional fields specific to Keycloak client credentials authentication.
type CommandAuthKeyCloakClientCredentials struct {
	// CommandAuthConfigKeyCloak is a reference to the base configuration needed for authentication to Keyfactor Command API
	CommandAuthConfigKeyCloak

	// ClientID is the client ID for Keycloak authentication
	ClientID string `json:"client_id;omitempty"`

	// ClientSecret is the client secret for Keycloak authentication
	ClientSecret string `json:"client_secret;omitempty"`

	// AccessToken is the access token for Keycloak authentication
	AccessToken string `json:"access_token;omitempty"`

	// RefreshToken is the refresh token for Keycloak authentication
	RefreshToken string `json:"refresh_token;omitempty"`

	// Expiry is the expiry time of the access token
	Expiry time.Time `json:"expiry;omitempty"`

	// Realm is the realm for Keycloak authentication
	Realm string `json:"realm;omitempty"`

	// TokenURL is the token URL for Keycloak authentication
	TokenURL string `json:"token_url"`
}

// Authenticate performs the authentication process for Keycloak using client credentials.
// It validates the authentication configuration, gets the token, and calls the base authentication method.
func (c *CommandAuthKeyCloakClientCredentials) Authenticate() error {
	c.AuthType = "client_credentials"
	cErr := c.ValidateAuthConfig()
	if cErr != nil {
		return cErr
	}

	//token, tErr := c.GetToken()
	//if tErr != nil {
	//	return tErr
	//}
	//if token == "" {
	//	return fmt.Errorf("failed to get Bearer token using client credentials")
	//}
	//
	//c.AuthHeader = fmt.Sprintf("Bearer %s", token)

	// create oauth client
	oauthy, err := auth_providers.NewOAuthAuthenticatorBuilder().
		WithClientId(c.ClientID).
		WithClientSecret(c.ClientSecret).
		WithTokenUrl(c.TokenURL).
		Build()

	if err != nil {
		return err
	}

	if oauthy != nil {
		oClient, oerr := oauthy.GetHttpClient()
		if oerr != nil {
			return oerr
		}
		c.SetClient(oClient)
	}

	aErr := c.CommandAuthConfig.Authenticate()
	if aErr != nil {
		return aErr
	}

	return nil
}

// setClientId sets the client ID for Keycloak authentication.
// It retrieves the client ID from environment variables if it's not set.
func (c *CommandAuthKeyCloakClientCredentials) setClientId() error {
	if c.ClientID == "" {
		if clientID, ok := os.LookupEnv(auth_providers.EnvKeyfactorClientID); ok {
			c.ClientID = clientID
		} else {
			return fmt.Errorf("client_id or environment variable %s is required", auth_providers.EnvKeyfactorClientID)
		}
	}
	return nil
}

// setClientSecret sets the client secret for Keycloak authentication.
// It retrieves the client secret from environment variables if it's not set.
func (c *CommandAuthKeyCloakClientCredentials) setClientSecret() error {
	if c.ClientSecret == "" {
		if clientSecret, ok := os.LookupEnv(auth_providers.EnvKeyfactorClientSecret); ok {
			c.ClientSecret = clientSecret
		} else {
			return fmt.Errorf(
				"client_secret or environment variable %s is required",
				auth_providers.EnvKeyfactorClientSecret,
			)
		}
	}
	return nil
}

// setRealm sets the realm for Keycloak authentication.
// It retrieves the realm from environment variables if it's not set.
func (c *CommandAuthKeyCloakClientCredentials) setRealm() error {
	if c.Realm == "" {
		if realm, ok := os.LookupEnv(EnvKeyfactorAuthRealm); ok {
			c.Realm = realm
		} else {
			c.Realm = DefaultKeyfactorAuthRealm
		}
	}
	return nil
}

// setTokenURL sets the token URL for Keycloak authentication.
// It generates the token URL if it's not set.
func (c *CommandAuthKeyCloakClientCredentials) setTokenURL() error {
	if c.TokenURL == "" {
		if tokenURL, ok := os.LookupEnv(auth_providers.EnvKeyfactorAuthTokenURL); ok {
			c.TokenURL = tokenURL
		} else {
			c.TokenURL = fmt.Sprintf(
				"https://%s:%s/realms/%s/protocol/openid-connect/token",
				c.AuthHostName,
				c.AuthPort,
				c.Realm,
			)
		}
	}
	return nil
}

// ValidateAuthConfig validates the authentication configuration for Keycloak using client credentials.
// It checks the client ID, client secret, realm, and token URL, and retrieves them from environment variables if they're not set.
func (c *CommandAuthKeyCloakClientCredentials) ValidateAuthConfig() error {
	cErr := c.CommandAuthConfigKeyCloak.ValidateAuthConfig()
	if cErr != nil {
		return cErr
	}

	cIdErr := c.setClientId()
	if cIdErr != nil {
		return cIdErr
	}

	cSecretErr := c.setClientSecret()
	if cSecretErr != nil {
		return cSecretErr
	}

	rErr := c.setRealm()
	if rErr != nil {
		return rErr
	}

	tErr := c.setTokenURL()
	if tErr != nil {
		return tErr

	}

	return c.CommandAuthConfig.ValidateAuthConfig()
}

// GetToken gets the access token for Keycloak authentication.
// It uses the refresh token if available and not expired, otherwise, it requests a new access token.
func (c *CommandAuthKeyCloakClientCredentials) GetToken() (string, error) {
	// Check if access token is set in environment variable
	if c.AccessToken == "" {
		if accessToken, ok := os.LookupEnv(auth_providers.EnvKeyfactorAccessToken); ok {
			c.AccessToken = accessToken

			// Don't try to refresh as we don't have a refresh token
			return c.AccessToken, nil
		}
	}

	if c.AccessToken != "" && time.Now().Before(c.Expiry) {
		return c.AccessToken, nil
	}

	// Use refresh token if available and not expired
	if c.RefreshToken != "" && time.Now().After(c.Expiry) {
		return c.refreshAccessToken()
	}

	// Otherwise, get a new access token using client credentials
	return c.requestNewToken()
}

// requestNewToken requests a new access token for Keycloak authentication using client credentials.
func (c *CommandAuthKeyCloakClientCredentials) requestNewToken() (string, error) {
	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_id", c.ClientID)
	formData.Set("client_secret", c.ClientSecret)

	return c.doTokenRequest(formData.Encode())
}

// refreshAccessToken refreshes the access token for Keycloak authentication.
func (c *CommandAuthKeyCloakClientCredentials) refreshAccessToken() (string, error) {
	formData := url.Values{}
	formData.Set("grant_type", "refresh_token")
	formData.Set("client_id", c.ClientID)
	formData.Set("client_secret", c.ClientSecret)
	formData.Set("refresh_token", c.RefreshToken)
	return c.doTokenRequest(formData.Encode())
}

// doTokenRequest sends a token request to Keycloak and handles the response.
func (c *CommandAuthKeyCloakClientCredentials) doTokenRequest(data string) (string, error) {
	requestBody := strings.NewReader(data)
	req, reqErr := http.NewRequest("POST", c.TokenURL, requestBody)
	if reqErr != nil {
		return "", reqErr
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, tkRespErr := c.HttpClient.Do(req)
	if tkRespErr != nil {
		return "", tkRespErr
	}
	defer resp.Body.Close()

	// check response status code
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, ioErr := io.ReadAll(resp.Body)
	if ioErr != nil {
		return "", ioErr
	}

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", err
	}

	c.AccessToken = tokenResponse.AccessToken
	c.RefreshToken = tokenResponse.RefreshToken
	c.Expiry = time.Now().Add(time.Duration(tokenResponse.ExpiresIn-30) * time.Second) // Subtract 30 seconds to account for delay

	return c.AccessToken, nil
}
