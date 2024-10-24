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
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultCommandPort    = 443
	DefaultCommandAPIPath = "KeyfactorAPI"
	DefaultAPIVersion     = "1"
	DefaultAPIClientName  = "APIClient"
	DefaultProductVersion = "10.5.0.0"
	DefaultConfigFilePath = ".keyfactor/command_config.json"
	DefaultConfigProfile  = "default"
	DefaultClientTimeout  = 60

	EnvKeyfactorHostName      = "KEYFACTOR_HOSTNAME"
	EnvKeyfactorPort          = "KEYFACTOR_PORT"
	EnvKeyfactorAPIPath       = "KEYFACTOR_API_PATH"
	EnvKeyfactorSkipVerify    = "KEYFACTOR_SKIP_VERIFY"
	EnvKeyfactorCACert        = "KEYFACTOR_CA_CERT"
	EnvKeyfactorAuthProvider  = "KEYFACTOR_AUTH_PROVIDER"
	EnvKeyfactorAuthProfile   = "KEYFACTOR_AUTH_CONFIG_PROFILE"
	EnvKeyfactorConfigFile    = "KEYFACTOR_AUTH_CONFIG_FILE"
	EnvKeyfactorClientTimeout = "KEYFACTOR_CLIENT_TIMEOUT"
)

// Authenticator is an interface for authentication to Keyfactor Command API.
type Authenticator interface {
	GetHttpClient() (*http.Client, error)
}

// roundTripperFunc is a helper type to create a custom RoundTripper
type roundTripperFunc func(req *http.Request) (*http.Response, error)

// RoundTrip executes a single HTTP transaction
func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// CommandAuthConfig represents the base configuration needed for authentication to Keyfactor Command API.
type CommandAuthConfig struct {
	// ConfigType is the type of configuration
	ConfigType string `json:"config_type"`

	//ConfigProfile is the profile of the configuration
	ConfigProfile string

	//ConfigFilePath is the path to the configuration file
	ConfigFilePath string

	// FileConfig
	FileConfig *Server

	// AuthHeader is the header to be used for authentication to Keyfactor Command API
	AuthHeader string `json:"auth_header"`

	// CommandHostName is the hostname of the Keyfactor Command API
	CommandHostName string `json:"host"`

	// CommandPort is the port of the Keyfactor Command API
	CommandPort int `json:"port"`

	// CommandAPIPath is the path of the Keyfactor Command API, default is "KeyfactorAPI"
	CommandAPIPath string `json:"api_path"`

	// CommandAPIVersion is the version of the Keyfactor Command API, default is "1"
	CommandVersion string `json:"command_version"`

	// CommandCACert is the CA certificate to be used for authentication to Keyfactor Command API for use with not widely trusted certificates. This can be a filepath or a string of the certificate in PEM format.
	CommandCACert string `json:"command_ca_cert"`

	// SkipVerify is a flag to skip verification of the server's certificate chain and host name. Default is false.
	SkipVerify bool `json:"skip_verify"`

	// HttpClientTimeout is the timeout for the http Client
	HttpClientTimeout int `json:"client_timeout"`

	// UserAgent is the user agent to be used for authentication to Keyfactor Command API
	UserAgent string `json:"user_agent,omitempty"`

	// Debug
	Debug bool `json:"debug,omitempty"`

	// HttpClient is the http Client to be used for authentication to Keyfactor Command API
	HttpClient *http.Client
}

func cleanHostName(hostName string) string {
	// check if hostname is a url and if so, extract the hostname
	if strings.Contains(hostName, "://") {
		hostName = strings.Split(hostName, "://")[1]
		//remove any trailing paths
		hostName = strings.Split(hostName, "/")[0]
		// remove any trailing slashes
		hostName = strings.TrimRight(hostName, "/")
	}
	return hostName
}

// WithCommandHostName sets the hostname for authentication to Keyfactor Command API.
func (c *CommandAuthConfig) WithCommandHostName(hostName string) *CommandAuthConfig {
	hostName = cleanHostName(hostName)
	c.CommandHostName = hostName
	return c
}

// WithCommandPort sets the port for authentication to Keyfactor Command API.
func (c *CommandAuthConfig) WithCommandPort(port int) *CommandAuthConfig {
	c.CommandPort = port
	return c
}

// WithCommandAPIPath sets the API path for authentication to Keyfactor Command API.
func (c *CommandAuthConfig) WithCommandAPIPath(apiPath string) *CommandAuthConfig {
	c.CommandAPIPath = apiPath
	return c
}

// WithCommandCACert sets the CA certificate for authentication to Keyfactor Command API.
func (c *CommandAuthConfig) WithCommandCACert(caCert string) *CommandAuthConfig {
	c.CommandCACert = caCert
	return c
}

// WithSkipVerify sets the flag to skip verification of the server's certificate chain and host name.
func (c *CommandAuthConfig) WithSkipVerify(skipVerify bool) *CommandAuthConfig {
	c.SkipVerify = skipVerify
	return c
}

// WithHttpClient sets the http Client for authentication to Keyfactor Command API.
func (c *CommandAuthConfig) WithHttpClient(client *http.Client) *CommandAuthConfig {
	c.HttpClient = client
	return c
}

// WithConfigFile sets the configuration file for authentication to Keyfactor Command API.
func (c *CommandAuthConfig) WithConfigFile(configFilePath string) *CommandAuthConfig {

	if c.ConfigProfile == "" {
		// check if profile is set in environment
		if profile, ok := os.LookupEnv(EnvKeyfactorAuthProfile); ok {
			c.ConfigProfile = profile
		} else {
			c.ConfigProfile = DefaultConfigProfile
		}
	}

	c.ConfigFilePath = configFilePath
	return c
}

// WithConfigProfile sets the configuration profile for authentication to Keyfactor Command API.
func (c *CommandAuthConfig) WithConfigProfile(profile string) *CommandAuthConfig {
	if profile == "" {
		// check if profile is set in environment
		if p, ok := os.LookupEnv(EnvKeyfactorAuthProfile); ok {
			c.ConfigProfile = p
		} else {
			c.ConfigProfile = DefaultConfigProfile
		}
	} else {
		c.ConfigProfile = profile
	}
	return c
}

// WithClientTimeout sets the timeout for the http Client.
func (c *CommandAuthConfig) WithClientTimeout(timeout int) *CommandAuthConfig {
	c.HttpClientTimeout = timeout
	return c
}

// ValidateAuthConfig validates the authentication configuration for Keyfactor Command API.
func (c *CommandAuthConfig) ValidateAuthConfig() error {
	if c.CommandHostName == "" {
		if hostName, ok := os.LookupEnv(EnvKeyfactorHostName); ok {
			c.CommandHostName = cleanHostName(hostName)
		} else {
			if c.FileConfig != nil && c.FileConfig.Host != "" {
				c.CommandHostName = cleanHostName(c.FileConfig.Host)
			} else {
				return fmt.Errorf("command_host_name or environment variable %s is required", EnvKeyfactorHostName)
			}
		}
	}
	if c.CommandPort <= 0 {
		if port, ok := os.LookupEnv(EnvKeyfactorPort); ok {
			configPort, pErr := strconv.Atoi(port)
			if pErr == nil {
				c.CommandPort = configPort
			}
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
	if c.HttpClientTimeout <= 0 {
		if timeout, ok := os.LookupEnv(EnvKeyfactorClientTimeout); ok {
			configTimeout, tErr := strconv.Atoi(timeout)
			if tErr == nil {
				c.HttpClientTimeout = configTimeout
			}
		} else {
			c.HttpClientTimeout = DefaultClientTimeout
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

// BuildTransport creates a custom http Transport for authentication to Keyfactor Command API.
func (c *CommandAuthConfig) BuildTransport() (*http.Transport, error) {
	output := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			Renegotiation: tls.RenegotiateOnceAsClient,
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if c.SkipVerify {
		output.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Load the system certs
	if c.CommandCACert != "" {
		rootCAs, pErr := x509.SystemCertPool()
		if pErr != nil {
			return nil, pErr
		}
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}

		// check if CommandCACert is a file
		if _, err := os.Stat(c.CommandCACert); err == nil {
			cert, ioErr := os.ReadFile(c.CommandCACert)
			if ioErr != nil {
				return nil, ioErr
			}
			// Append your custom cert to the pool
			if ok := rootCAs.AppendCertsFromPEM(cert); !ok {
				return nil, fmt.Errorf("failed to append custom CA cert to pool")
			}
		} else {
			// Append your custom cert to the pool
			if ok := rootCAs.AppendCertsFromPEM([]byte(c.CommandCACert)); !ok {
				return nil, fmt.Errorf("failed to append custom CA cert to pool")
			}
		}

		output.TLSClientConfig.RootCAs = rootCAs
	}
	return output, nil
}

// SetClient sets the http Client for authentication to Keyfactor Command API.
func (c *CommandAuthConfig) SetClient(client *http.Client) *http.Client {
	if client != nil {
		c.HttpClient = client
	}
	if c.HttpClient == nil {
		c.HttpClient = &http.Client{}
	}
	return c.HttpClient
}

// updateCACerts updates the CA certs for the http Client.
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

	// ensure Client is set
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

	// Trust the augmented cert pool in our Client
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

	c.HttpClient.Timeout = time.Duration(c.HttpClientTimeout) * time.Second

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

// LoadCACertificates loads the custom CA certificates from a file.
func LoadCACertificates(certFile string) (*x509.CertPool, error) {
	// Read the file containing the custom CA certificate
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	// Create a new CertPool and append the custom CA certificate
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(certBytes); !ok {
		return nil, err
	}

	return certPool, nil
}

// FindCACertificate reads the CA certificate from a file and returns a slice of x509.Certificate.
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

// DecodePEMBytes decodes the PEM encoded bytes into a slice of PEM blocks.
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

// LoadConfig loads the configuration file and returns the server configuration.
func (c *CommandAuthConfig) LoadConfig(profile string, configFilePath string, silentLoad bool) (
	*Server,
	error,
) {
	if configFilePath == "" {
		// check if config file is set in environment
		if config, ok := os.LookupEnv(EnvKeyfactorConfigFile); ok {
			configFilePath = config
		} else {
			homedir, err := os.UserHomeDir()
			if err != nil {
				homedir = os.Getenv("HOME")
			}
			configFilePath = fmt.Sprintf("%s/%s", homedir, DefaultConfigFilePath)
		}
	} else {
		c.ConfigFilePath = configFilePath
	}
	expandedPath, err := expandPath(configFilePath)
	if err != nil {
		if !silentLoad {
			return nil, err
		}
		// if silentLoad is true then eat the error and return nil
		return nil, nil
	}

	file, err := os.Open(expandedPath)
	if err != nil {
		if !silentLoad {
			return nil, err
		}
		// if silentLoad is true then eat the error and return nil
		return nil, nil
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	if jErr := decoder.Decode(&config); jErr != nil {
		if !silentLoad {
			return nil, jErr
		}
		// if silentLoad is true then eat the error and return nil
		return nil, nil
	}

	if profile == "" {
		if c.ConfigProfile != "" {
			profile = c.ConfigProfile
		} else {
			profile = DefaultConfigProfile
		}
	}

	server, ok := config.Servers[profile]
	if !ok {
		if !silentLoad {
			return nil, fmt.Errorf("profile %s not found in config file", profile)
		}
		// if silentLoad is true then eat the error and return nil
		return nil, nil
	}

	c.FileConfig = &server

	if !silentLoad {
		c.CommandHostName = server.Host
		c.CommandPort = server.Port
		c.CommandAPIPath = server.APIPath
		c.CommandCACert = server.CACertPath
		c.SkipVerify = server.SkipTLSVerify
	} else {
		if c.CommandHostName == "" {
			c.CommandHostName = server.Host
		}
		if c.CommandPort <= 0 {
			c.CommandPort = server.Port
		}
		if c.CommandAPIPath == "" {
			c.CommandAPIPath = server.APIPath
		}
		if c.CommandCACert == "" {
			c.CommandCACert = server.CACertPath
		}
		if c.SkipVerify {
			c.SkipVerify = server.SkipTLSVerify
		}
	}
	return &server, nil
}

// expandPath expands the path to include the user's home directory.
func expandPath(path string) (string, error) {
	if path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

func (c *CommandAuthConfig) GetServerConfig() *Server {
	server := Server{
		Host:          c.CommandHostName,
		Port:          c.CommandPort,
		Username:      "",
		Password:      "",
		Domain:        "",
		ClientID:      "",
		ClientSecret:  "",
		OAuthTokenUrl: "",
		APIPath:       c.CommandAPIPath,
		AuthProvider:  AuthProvider{},
		SkipTLSVerify: c.SkipVerify,
		CACertPath:    c.CommandCACert,
		AuthType:      "",
	}
	return &server
}
