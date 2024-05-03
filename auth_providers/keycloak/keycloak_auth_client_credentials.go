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
)

const (
	DefaultKeyfactorAuthPort = "8444"
	DefaultKeyfactorRealm    = "Keyfactor"
	EnvKeyfactorClientID     = "KEYFACTOR_CLIENT_ID"
	EnvKeyfactorClientSecret = "KEYFACTOR_CLIENT_SECRET"
	EnvKeyfactorAuthRealm    = "KEYFACTOR_AUTH_REALM"
	EnvKeyfactorAuthTokenURL = "KEYFACTOR_AUTH_TOKEN_URL"
)

func (c *CommandAuthKeyCloakClientCredentials) Authenticate() error {
	c.HttpClient = &http.Client{}
	c.AuthType = "client_credentials"
	cErr := c.ValidateAuthConfig()
	if cErr != nil {
		return cErr
	}

	token, tErr := c.GetToken()
	if tErr != nil {
		return tErr
	}
	if token == "" {
		return fmt.Errorf("failed to get Bearer token using client credentials")
	}

	c.AuthHeader = fmt.Sprintf("Bearer %s", token)

	return nil
}

func (c *CommandAuthKeyCloakClientCredentials) ValidateAuthConfig() error {
	cErr := c.CommandAuthConfigKeyCloak.ValidateAuthConfig()
	if cErr != nil {
		return cErr
	}

	if c.ClientID == "" {
		if clientID, ok := os.LookupEnv(EnvKeyfactorClientID); ok {
			c.ClientID = clientID
		} else {
			return fmt.Errorf("client_id or environment variable %s is required", EnvKeyfactorClientID)
		}
	}
	if c.ClientSecret == "" {
		if clientSecret, ok := os.LookupEnv(EnvKeyfactorClientSecret); ok {
			c.ClientSecret = clientSecret
		} else {
			return fmt.Errorf("client_secret or environment variable %s is required", EnvKeyfactorClientSecret)
		}
	}
	if c.Realm == "" {
		if realm, ok := os.LookupEnv(EnvKeyfactorAuthRealm); ok {
			c.Realm = realm
		} else {
			c.Realm = DefaultKeyfactorRealm
		}
	}

	if c.TokenURL == "" {
		if tokenURL, ok := os.LookupEnv(EnvKeyfactorAuthTokenURL); ok {
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

func (c *CommandAuthKeyCloakClientCredentials) GetToken() (string, error) {
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

func (c *CommandAuthKeyCloakClientCredentials) requestNewToken() (string, error) {
	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_id", c.ClientID)
	formData.Set("client_secret", c.ClientSecret)

	return c.doTokenRequest(formData.Encode())
}

func (c *CommandAuthKeyCloakClientCredentials) refreshAccessToken() (string, error) {
	formData := url.Values{}
	formData.Set("grant_type", "refresh_token")
	formData.Set("client_id", c.ClientID)
	formData.Set("client_secret", c.ClientSecret)
	formData.Set("refresh_token", c.RefreshToken)
	return c.doTokenRequest(formData.Encode())
}

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
