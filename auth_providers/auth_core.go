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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	DefaultCommandPort       = "443"
	DefaultCommandAPIPath    = "KeyfactorAPI"
	DefaultAPIVersion        = "1"
	DefaultAPIClientName     = "APIClient"
	DefaultProductVersion    = "10.5.0.0"
	EnvKeyfactorHostName     = "KEYFACTOR_HOSTNAME"
	EnvKeyfactorPort         = "KEYFACTOR_PORT"
	EnvKeyfactorAPIPath      = "KEYFACTOR_API_PATH"
	EnvKeyfactorSkipVerify   = "KEYFACTOR_SKIP_VERIFY"
	EnvKeyfactorCACert       = "KEYFACTOR_CA_CERT"
	EnvKeyfactorAuthProvider = "KEYFACTOR_AUTH_PROVIDER"
)

// Authenticator is an interface for authentication to Keyfactor Command API.
type Authenticator interface {
	GetHttpClient() (*http.Client, error)
}

// CommandAuthConfig represents the base configuration needed for authentication to Keyfactor Command API.
type CommandAuthConfig struct {
	// ConfigType is the type of configuration
	ConfigType string `json:"config_type"`

	// AuthHeader is the header to be used for authentication to Keyfactor Command API
	AuthHeader string `json:"auth_header"`

	// CommandHostName is the hostname of the Keyfactor Command API
	CommandHostName string `json:"command_host_name"`

	// CommandPort is the port of the Keyfactor Command API
	CommandPort string `json:"command_port"`

	// CommandAPIPath is the path of the Keyfactor Command API, default is "KeyfactorAPI"
	CommandAPIPath string `json:"command_api_path"`

	// CommandAPIVersion is the version of the Keyfactor Command API, default is "1"
	CommandVersion string `json:"command_version"`

	// CommandCACert is the CA certificate to be used for authentication to Keyfactor Command API for use with not widely trusted certificates. This can be a filepath or a string of the certificate in PEM format.
	CommandCACert string `json:"command_ca_cert"`

	// SkipVerify is a flag to skip verification of the server's certificate chain and host name. Default is false.
	SkipVerify bool `json:"skip_verify"`

	// HttpClient is the http client to be used for authentication to Keyfactor Command API
	HttpClient *http.Client
}

func (c *CommandAuthConfig) WithCommandHostName(hostName string) *CommandAuthConfig {
	c.CommandHostName = hostName
	return c
}

func (c *CommandAuthConfig) WithCommandPort(port string) *CommandAuthConfig {
	c.CommandPort = port
	return c
}

func (c *CommandAuthConfig) WithCommandAPIPath(apiPath string) *CommandAuthConfig {
	c.CommandAPIPath = apiPath
	return c
}

func (c *CommandAuthConfig) WithCommandCACert(caCert string) *CommandAuthConfig {
	c.CommandCACert = caCert
	return c
}

func (c *CommandAuthConfig) WithSkipVerify(skipVerify bool) *CommandAuthConfig {
	c.SkipVerify = skipVerify
	return c
}

func (c *CommandAuthConfig) WithHttpClient(client *http.Client) *CommandAuthConfig {
	c.HttpClient = client
	return c
}

// ValidateAuthConfig validates the authentication configuration for Keyfactor Command API.
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
	c.SetClient(nil)

	// check for skip verify in environment
	if skipVerify, ok := os.LookupEnv(EnvKeyfactorSkipVerify); ok {
		c.SkipVerify = skipVerify == "true" || skipVerify == "1"
	}

	if c.SkipVerify {
		c.HttpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		return nil
	}

	caErr := c.updateCACerts()
	if caErr != nil {
		return caErr
	}

	return nil
}

// SetClient sets the http client for authentication to Keyfactor Command API.
func (c *CommandAuthConfig) SetClient(client *http.Client) *http.Client {
	if client != nil {
		c.HttpClient = client
	}
	if c.HttpClient == nil {
		c.HttpClient = &http.Client{}
	}
	return c.HttpClient
}

// updateCACerts updates the CA certs for the http client.
func (c *CommandAuthConfig) updateCACerts() error {
	// check if CommandCACert is set
	if c.CommandCACert == "" {
		// check if CommandCACert is set in environment
		if caCert, ok := os.LookupEnv(EnvKeyfactorCACert); ok {
			c.CommandCACert = caCert
		} else {
			return nil
		}
	}

	// ensure client is set
	c.SetClient(nil)

	// Load the system certs
	rootCAs, pErr := x509.SystemCertPool()
	if pErr != nil {
		return pErr
	}
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// check if CommandCACert is a file
	if _, err := os.Stat(c.CommandCACert); err == nil {
		cert, ioErr := os.ReadFile(c.CommandCACert)
		if ioErr != nil {
			return ioErr
		}
		// Append your custom cert to the pool
		if ok := rootCAs.AppendCertsFromPEM(cert); !ok {
			return fmt.Errorf("failed to append custom CA cert to pool")
		}
	} else {
		// Append your custom cert to the pool
		if ok := rootCAs.AppendCertsFromPEM([]byte(c.CommandCACert)); !ok {
			return fmt.Errorf("failed to append custom CA cert to pool")
		}
	}

	// Trust the augmented cert pool in our client
	c.HttpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: rootCAs,
		},
	}

	return nil
}

// Authenticate performs the authentication test to Keyfactor Command API and sets Command product version.
func (c *CommandAuthConfig) Authenticate() error {
	// call /Status/Endpoints API to validate credentials
	c.SetClient(nil)

	//create headers for request
	headers := map[string]string{
		"Content-Type":               "application/json",
		"Accept":                     "application/json",
		"x-keyfactor-api-version":    DefaultAPIVersion,
		"x-keyfactor-requested-with": DefaultAPIClientName,
	}

	if c.AuthHeader != "" {
		headers["Authorization"] = c.AuthHeader
	}

	endPoint := fmt.Sprintf(
		"https://%s/%s/Status/Endpoints",
		c.CommandHostName,
		//c.CommandPort,
		c.CommandAPIPath,
	)

	// create request object
	req, rErr := http.NewRequest("GET", endPoint, nil)
	if rErr != nil {
		return rErr
	}
	// Set headers from the map
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	c.HttpClient.Timeout = 60 * time.Second

	cResp, cErr := c.HttpClient.Do(req)
	if cErr != nil {
		return cErr
	} else if cResp == nil {
		return fmt.Errorf("failed to authenticate, no response received from Keyfactor Command")
	}

	defer cResp.Body.Close()

	// check if body is empty
	if cResp.Body == nil {
		return fmt.Errorf("failed to authenticate, empty response body received from Keyfactor Command")
	}

	cRespBody, ioErr := io.ReadAll(cResp.Body)
	if ioErr != nil {
		return ioErr
	}

	if cResp.StatusCode != 200 {
		//convert body to string
		return fmt.Errorf(
			"failed to authenticate, received status code %d from Keyfactor Command: %s",
			cResp.StatusCode,
			string(cRespBody),
		)
	}

	productVersion := cResp.Header.Get("x-keyfactor-product-version")
	if productVersion != "" {
		c.CommandVersion = productVersion
	} else {
		c.CommandVersion = DefaultProductVersion
	}

	//decode response to json
	var response []string
	if err := json.Unmarshal(cRespBody, &response); err != nil {
		return err
	}

	return nil

}

func FindCACertificate(caCertificatePath string) ([]*x509.Certificate, error) {
	if caCertificatePath == "" {
		return nil, nil
	}

	buf, err := os.ReadFile(caCertificatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate file at path %s: %w", caCertificatePath, err)
	}
	// Decode the PEM encoded certificates into a slice of PEM blocks
	chainBlocks, _, err := DecodePEMBytes(buf)
	if err != nil {
		return nil, err
	}
	if len(chainBlocks) <= 0 {
		return nil, fmt.Errorf("didn't find certificate in file at path %s", caCertificatePath)
	}

	var caChain []*x509.Certificate
	for _, block := range chainBlocks {
		// Parse the PEM block into an x509 certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
		}

		caChain = append(caChain, cert)
	}

	return caChain, nil
}

func DecodePEMBytes(buf []byte) ([]*pem.Block, []byte, error) {
	var privKey []byte
	var certificates []*pem.Block
	var block *pem.Block
	for {
		block, buf = pem.Decode(buf)
		if block == nil {
			break
		} else if strings.Contains(block.Type, "PRIVATE KEY") {
			privKey = pem.EncodeToMemory(block)
		} else {
			certificates = append(certificates, block)
		}
	}
	return certificates, privKey, nil
}
