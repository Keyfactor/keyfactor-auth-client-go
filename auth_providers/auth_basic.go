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
)

var _ Authenticator = &BasicAuthAuthenticator{}

type BasicAuthAuthenticator struct {
	client *http.Client
}

func BasicAuthTransport(username, password string) *http.Client {
	// Encode the username and password in Base64
	auth := username + ":" + password
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))

	// Create a custom RoundTripper
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		// You can customize other transport settings here
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
	}
}

// roundTripperFunc is a helper type to create a custom RoundTripper
type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func (b *BasicAuthAuthenticator) GetHttpClient() (*http.Client, error) {
	return b.client, nil
}

// CommandAuthConfigBasic represents the base configuration needed for authentication to Keyfactor Command API.
type CommandAuthConfigBasic struct {
	// CommandAuthConfig is a reference to the base configuration needed for authentication to Keyfactor Command API
	CommandAuthConfig

	// Username is the username to be used for authentication to Keyfactor Command API
	Username string `json:"username"`

	// Password is the password to be used for authentication to Keyfactor Command API
	Password string `json:"password"`
}

func NewBasicAuthAuthenticatorBuilder() *CommandAuthConfigBasic {
	return &CommandAuthConfigBasic{}
}

func (a *CommandAuthConfigBasic) WithUsername(username string) *CommandAuthConfigBasic {
	a.Username = username
	return a
}

func (a *CommandAuthConfigBasic) WithPassword(password string) *CommandAuthConfigBasic {
	a.Password = password
	return a
}

func (a *CommandAuthConfigBasic) Build() (Authenticator, error) {

	client := BasicAuthTransport(a.Username, a.Password)
	a.HttpClient = client

	return &BasicAuthAuthenticator{client: client}, nil
}

func (a *CommandAuthConfigBasic) ValidateAuthConfig() error {
	if a.Username == "" {
		return fmt.Errorf("username is required")
	}
	if a.Password == "" {
		return fmt.Errorf("password is required")
	}

	return a.CommandAuthConfig.ValidateAuthConfig()
}

func (a *CommandAuthConfigBasic) Authenticate() error {
	cErr := a.ValidateAuthConfig()
	if cErr != nil {
		return cErr
	}
	//basicAuth := fmt.Sprintf("%s:%s", c.Username, c.Password)
	//basicAuth = base64.StdEncoding.EncodeToString([]byte(basicAuth))
	//c.AuthHeader = fmt.Sprintf("Basic %s", basicAuth)

	// create oauth client
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
