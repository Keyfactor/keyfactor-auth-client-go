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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
)

const (
	EnvKeyfactorAuthHostname = "KEYFACTOR_AUTH_HOSTNAME"
	EnvKeyfactorAuthPort     = "KEYFACTOR_AUTH_PORT"
	EnvAuthCACert            = "KEYFACTOR_AUTH_CA_CERT"
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

	// Auth CA Cert is the CA certificate to be used for authentication to Keycloak for use with not widely trusted certificates. This can be a filepath or a string of the certificate in PEM format.
	AuthCACert string `json:"auth_ca_cert"`
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

	caErr := c.updateCACerts()
	if caErr != nil {
		return caErr
	}
	return nil
}

func (c *CommandAuthConfigKeyCloak) updateCACerts() error {
	// check if CommandCACert is set
	if c.AuthCACert == "" {
		// check environment for auth CA cert
		if authCACert, ok := os.LookupEnv(EnvAuthCACert); ok {
			c.AuthCACert = authCACert
		} else {
			return nil
		}
	}

	// Load the system certs
	rootCAs, pErr := x509.SystemCertPool()
	if pErr != nil {
		return pErr
	}
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// check if CommandCACert is a file
	if _, err := os.Stat(c.AuthCACert); err == nil {
		cert, ioErr := os.ReadFile(c.AuthCACert)
		if ioErr != nil {
			return ioErr
		}
		// Append your custom cert to the pool
		if ok := rootCAs.AppendCertsFromPEM(cert); !ok {
			return fmt.Errorf("failed to append custom CA cert to pool")
		}
	} else {
		// Append your custom cert to the pool
		if ok := rootCAs.AppendCertsFromPEM([]byte(c.AuthCACert)); !ok {
			return fmt.Errorf("failed to append custom CA cert to pool")
		}
	}

	// check if client already has a tls config
	if c.HttpClient.Transport == nil {
		// Trust the augmented cert pool in our client
		c.HttpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
			},
		}
	} else {
		// Trust the augmented cert pool in our client
		c.HttpClient.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
			RootCAs: rootCAs,
		}
	}

	return nil
}
