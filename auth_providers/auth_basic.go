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
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
)

const (
	EnvKeyfactorUsername = "KEYFACTOR_USERNAME"
	EnvKeyfactorPassword = "KEYFACTOR_PASSWORD"
)

// Basic Authenticator
var _ Authenticator = &BasicAuthAuthenticator{}

// BasicAuthAuthenticator is an Authenticator that uses Basic Auth for authentication.
type BasicAuthAuthenticator struct {
	Client *http.Client
}

// GetHttpClient returns the http client
func (b *BasicAuthAuthenticator) GetHttpClient() (*http.Client, error) {
	return b.Client, nil
}

// CommandAuthConfigBasic represents the base configuration needed for authentication to Keyfactor Command API.
type CommandAuthConfigBasic struct {
	// CommandAuthConfig is a reference to the base configuration needed for authentication to Keyfactor Command API
	CommandAuthConfig

	// Username is the username to be used for authentication to Keyfactor Command API
	Username string `json:"username,omitempty"`

	// Password is the password to be used for authentication to Keyfactor Command API
	Password string `json:"password,omitempty"`
}

// NewBasicAuthAuthenticatorBuilder creates a new instance of CommandAuthConfigBasic
func NewBasicAuthAuthenticatorBuilder() *CommandAuthConfigBasic {
	return &CommandAuthConfigBasic{}
}

// WithUsername sets the username for authentication
func (a *CommandAuthConfigBasic) WithUsername(username string) *CommandAuthConfigBasic {
	a.Username = username
	return a
}

// WithPassword sets the password for authentication
func (a *CommandAuthConfigBasic) WithPassword(password string) *CommandAuthConfigBasic {
	a.Password = password
	return a
}

// GetHttpClient returns the http client
func (a *CommandAuthConfigBasic) GetHttpClient() (*http.Client, error) {
	//validate the configuration
	cErr := a.ValidateAuthConfig()
	if cErr != nil {
		return nil, cErr
	}

	// Encode the username and password in Base64
	auth := a.Username + ":" + a.Password
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))

	// Create a custom RoundTripper
	transport, tErr := a.CommandAuthConfig.BuildTransport()
	if tErr != nil {
		return nil, tErr
	}

	return &http.Client{
		Transport: roundTripperFunc(
			func(req *http.Request) (*http.Response, error) {
				// Add the Authorization header to the request
				req.Header.Set("Authorization", "Basic "+encodedAuth)

				// Forward the request to the actual transport
				return transport.RoundTrip(req)
			},
		),
	}, nil
}

// Build creates a new instance of BasicAuthAuthenticator
func (a *CommandAuthConfigBasic) Build() (Authenticator, error) {

	client, cErr := a.GetHttpClient()
	if cErr != nil {
		return nil, cErr
	}
	a.HttpClient = client

	return &BasicAuthAuthenticator{Client: client}, nil
}

// ValidateAuthConfig validates the configuration
func (a *CommandAuthConfigBasic) ValidateAuthConfig() error {
	serverConfig, _ := a.CommandAuthConfig.LoadConfig(
		a.CommandAuthConfig.ConfigProfile,
		a.CommandAuthConfig.ConfigFilePath,
	)
	if a.Username == "" {
		if username, ok := os.LookupEnv(EnvKeyfactorUsername); ok {
			a.Username = username
		} else {
			if serverConfig != nil && serverConfig.Username != "" {
				a.Username = serverConfig.Username
			} else {
				return fmt.Errorf("username or environment variable %s is required", EnvKeyfactorUsername)
			}
		}
	}
	if a.Password == "" {
		if password, ok := os.LookupEnv(EnvKeyfactorPassword); ok {
			a.Password = password
		} else {
			if serverConfig != nil && serverConfig.Password != "" {
				a.Password = serverConfig.Password
			} else {
				return fmt.Errorf("password or environment variable %s is required", EnvKeyfactorPassword)
			}
		}
	}

	return a.CommandAuthConfig.ValidateAuthConfig()
}

// Authenticate authenticates the user
func (a *CommandAuthConfigBasic) Authenticate() error {
	cErr := a.ValidateAuthConfig()
	if cErr != nil {
		return cErr
	}

	// create oauth Client
	authy, err := NewBasicAuthAuthenticatorBuilder().
		WithUsername(a.Username).
		WithPassword(a.Password).
		Build()

	if err != nil {
		return err
	}

	if authy != nil {
		bClient, berr := authy.GetHttpClient()
		if berr != nil {
			return berr
		}
		a.SetClient(bClient)
	}

	return a.CommandAuthConfig.Authenticate()
}
