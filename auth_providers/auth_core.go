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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultCommandPort is the default port for Keyfactor Command API
	DefaultCommandPort = 443

	// DefaultCommandAPIPath is the default path for Keyfactor Command API
	DefaultCommandAPIPath = "KeyfactorAPI"

	// DefaultAPIVersion is the default version for Keyfactor Command API
	DefaultAPIVersion = "1"

	// DefaultAPIClientName is the default client name for Keyfactor Command API
	DefaultAPIClientName = "APIClient"

	// DefaultProductVersion is the default product version for Keyfactor Command API
	DefaultProductVersion = "10.5.0.0"

	// DefaultConfigFilePath is the default path for the configuration file
	DefaultConfigFilePath = ".keyfactor/command_config.json"

	// DefaultConfigProfile is the default profile for the configuration file
	DefaultConfigProfile = "default"

	// DefaultClientTimeout is the default timeout for the http Client
	DefaultClientTimeout = 60

	//Default HTTP protocol
	DefaultHttpProtocol = "https"

	// EnvKeyfactorHostName is the environment variable for the Keyfactor Command hostname
	EnvKeyfactorHostName = "KEYFACTOR_HOSTNAME"

	// EnvKeyfactorPort is the environment variable for the Keyfactor Command http(s) port
	EnvKeyfactorPort = "KEYFACTOR_PORT"

	// EnvKeyfactorAPIPath is the environment variable for the Keyfactor Command API path
	EnvKeyfactorAPIPath = "KEYFACTOR_API_PATH"

	// EnvKeyfactorSkipVerify is the environment variable for skipping TLS verification when communicating with Keyfactor Command
	EnvKeyfactorSkipVerify = "KEYFACTOR_SKIP_VERIFY"

	// EnvKeyfactorCACert is the environment variable for the CA certificate to be used for TLS verification when communicating with Keyfactor Command API
	EnvKeyfactorCACert = "KEYFACTOR_CA_CERT"

	// EnvKeyfactorAuthProvider is the environment variable for the authentication provider to be used for Keyfactor Command API
	EnvKeyfactorAuthProvider = "KEYFACTOR_AUTH_PROVIDER"

	// EnvKeyfactorAuthProfile is the environment variable for the profile of the configuration file
	EnvKeyfactorAuthProfile = "KEYFACTOR_AUTH_CONFIG_PROFILE"

	// EnvKeyfactorConfigFile is the environment variable for the configuration file to reference for connecting to the Keyfactor Command API
	EnvKeyfactorConfigFile = "KEYFACTOR_AUTH_CONFIG_FILE"

	// EnvKeyfactorClientTimeout is the environment variable for the timeout for the http Client
	EnvKeyfactorClientTimeout = "KEYFACTOR_CLIENT_TIMEOUT"
)

// These transport-level timeouts govern connection pool/handshake behavior,
// not the overall request deadline (that's HttpClientTimeout, which drives
// ResponseHeaderTimeout). They are fixed, sane defaults -- matching
// net/http.DefaultTransport -- and must never scale with HttpClientTimeout;
// see newHTTPTransport's doc comment for the resource-leak history behind
// this.
const (
	// DefaultIdleConnTimeout is how long an idle pooled connection is
	// retained before being closed. Matches net/http.DefaultTransport.
	DefaultIdleConnTimeout = 90 * time.Second

	// DefaultExpectContinueTimeout is how long to wait for a "100 Continue"
	// response before sending the request body. Matches
	// net/http.DefaultTransport.
	DefaultExpectContinueTimeout = 1 * time.Second

	// DefaultTLSHandshakeTimeout is how long to wait for the TLS handshake
	// to complete. Matches net/http.DefaultTransport.
	DefaultTLSHandshakeTimeout = 10 * time.Second
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
	ConfigType string `json:"config_type,omitempty" yaml:"config_type,omitempty"`

	//ConfigProfile is the profile of the configuration
	ConfigProfile string

	//ConfigFilePath is the path to the configuration file
	ConfigFilePath string

	// FileConfig
	FileConfig *Server

	// AuthHeader is the header to be used for authentication to Keyfactor Command API
	AuthHeader string `json:"auth_header,omitempty" yaml:"auth_header,omitempty"`

	// CommandHostName is the hostname of the Keyfactor Command API
	CommandHostName string `json:"host,omitempty" yaml:"host,omitempty"`

	// CommandPort is the port of the Keyfactor Command API
	CommandPort int `json:"port,omitempty" yaml:"port,omitempty"`

	// CommandAPIPath is the path of the Keyfactor Command API, default is "KeyfactorAPI"
	CommandAPIPath string `json:"api_path,omitempty" yaml:"api_path,omitempty"`

	// CommandAPIVersion is the version of the Keyfactor Command API, default is "1"
	CommandVersion string `json:"command_version,omitempty" yaml:"command_version,omitempty"`

	// CommandCACert is the CA certificate to be used for authentication to Keyfactor Command API for use with not widely trusted certificates. This can be a filepath or a string of the certificate in PEM format.
	CommandCACert string `json:"command_ca_cert,omitempty" yaml:"command_ca_cert,omitempty"`

	// SkipVerify is a flag to skip verification of the server's certificate chain and host name. Default is false.
	SkipVerify bool `json:"skip_verify,omitempty" yaml:"skip_verify,omitempty"`

	// HttpClientTimeout is the timeout for the http Client
	HttpClientTimeout int `json:"client_timeout,omitempty" yaml:"client_timeout,omitempty"`

	// UserAgent is the user agent to be used for authentication to Keyfactor Command API
	UserAgent string `json:"user_agent,omitempty" yaml:"user_agent,omitempty"`

	// Debug
	Debug bool `json:"debug,omitempty" yaml:"debug,omitempty"`

	// HTTPProtocol
	HttpProtocol string `json:"http_protocol,omitempty" yaml:"http_protocol,omitempty"`

	// HttpClient is the http Client to be used for authentication to Keyfactor Command API
	HttpClient *http.Client
	//DefaultHttpClient *http.Client

	// clientTimeoutDefaulted records whether HttpClientTimeout's current
	// value was synthesized by ValidateAuthConfig's package-default fallback
	// (DefaultClientTimeout) rather than explicitly configured by the caller
	// (struct field, WithClientTimeout(), the KEYFACTOR_CLIENT_TIMEOUT env
	// var, or an existing FileConfig value). GetServerConfig() consults this
	// to avoid persisting a value the user never chose -- see
	// TestCommandAuthConfig_PersistedDefaultConfigFile_DoesNotShadowEnvVar
	// for why persisting the synthesized default is actively harmful: it
	// gets written to disk, and on the next run is indistinguishable from a
	// real file-configured value, which by design takes precedence over the
	// env var and so permanently shadows it.
	clientTimeoutDefaulted bool
}

// GetCommandVersion returns the Keyfactor Command product version detected during authentication.
func (c CommandAuthConfig) GetCommandVersion() string {
	return c.CommandVersion
}

// cleanHostName cleans the hostname for authentication to Keyfactor Command API.
func cleanHostName(hostName string) string {
	// check if hostname is a URL and if so, extract the hostname
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

	//check for http or https prefix
	if strings.Contains(hostName, "http://") {
		c.HttpProtocol = "http"
	}

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
	// An explicit caller choice always overrides any earlier
	// ValidateAuthConfig-synthesized default -- see clientTimeoutDefaulted's
	// doc comment.
	c.clientTimeoutDefaulted = false
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
	c.CommandAPIPath = strings.Trim(c.CommandAPIPath, "/")
	if c.HttpClientTimeout <= 0 {
		if timeout, ok := os.LookupEnv(EnvKeyfactorClientTimeout); ok {
			configTimeout, tErr := strconv.Atoi(timeout)
			if tErr != nil {
				log.Printf(
					"[ERROR] invalid value %q for environment variable %s: %v; falling back to config file/default timeout",
					timeout, EnvKeyfactorClientTimeout, tErr,
				)
			} else if configTimeout <= 0 {
				log.Printf(
					"[WARN] environment variable %s must be a positive integer, got %d; falling back to config file/default timeout",
					EnvKeyfactorClientTimeout, configTimeout,
				)
			} else {
				c.HttpClientTimeout = configTimeout
			}
		}
		// Fall back to the value loaded from the config file (if any), then the
		// package default. This mirrors the CommandHostName fallback above and
		// ensures an unset/unparseable env var can never leave HttpClientTimeout
		// at its zero value, which would otherwise disable http.Client/Transport
		// timeouts entirely (see issue tracking the unbounded-wait hazard).
		if c.HttpClientTimeout <= 0 {
			if c.FileConfig != nil && c.FileConfig.ClientTimeout > 0 {
				c.HttpClientTimeout = c.FileConfig.ClientTimeout
			} else {
				c.HttpClientTimeout = DefaultClientTimeout
				// This value was synthesized, not chosen -- see
				// clientTimeoutDefaulted's doc comment. GetServerConfig()
				// must not persist it.
				c.clientTimeoutDefaulted = true
			}
		}
	}

	if c.CommandCACert == "" {
		// check if CommandCACert is set in environment
		if caCert, ok := os.LookupEnv(EnvKeyfactorCACert); ok {
			c.CommandCACert = caCert
		}
	}

	// check for skip verify in environment
	if skipVerify, ok := os.LookupEnv(EnvKeyfactorSkipVerify); ok {
		c.SkipVerify = skipVerify == "true" || skipVerify == "1"
	}
	return nil
}

// newHTTPTransport builds the *http.Transport shared by BuildTransport and
// SetClient's zero-value client construction.
//
// Only ResponseHeaderTimeout is derived from CommandAuthConfig.HttpClientTimeout,
// since it is the one true per-request deadline here -- it's what surfaces to
// callers as "net/http: timeout awaiting response headers" and is the field a
// large HttpClientTimeout (e.g. 1800s for slow PFX enrollments) is meant to
// fix.
//
// IdleConnTimeout, ExpectContinueTimeout, and TLSHandshakeTimeout are pinned
// to fixed, sane defaults instead of scaling with HttpClientTimeout:
//
//   - IdleConnTimeout governs how long an *idle* pooled connection is kept
//     around, not a request deadline. Tying it to HttpClientTimeout meant a
//     large configured timeout (needed for slow requests) also kept every
//     idle socket -- and its goroutine -- alive for that same duration. A
//     `terraform apply` issuing many sequential requests at a 1800s timeout
//     therefore leaked hundreds of open sockets/goroutines for half an hour;
//     at a 1s timeout everything was released almost immediately. We use
//     net/http.DefaultTransport's default of 90s.
//   - ExpectContinueTimeout is how long to wait for a "100 Continue" response
//     before sending the request body; it's unrelated to the response
//     deadline. We use net/http.DefaultTransport's default of 1s.
//   - TLSHandshakeTimeout is a handshake deadline, not an idle-resource
//     timeout, so it doesn't contribute to the leak above. It's pinned here
//     anyway (rather than left scaling with HttpClientTimeout) on the same
//     principle: a hung TLS handshake should fail fast and free the
//     connection attempt independent of how long the caller is willing to
//     wait for a slow response body. We use net/http.DefaultTransport's
//     default of 10s.
func (c *CommandAuthConfig) newHTTPTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			Renegotiation: tls.RenegotiateOnceAsClient,
		},
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: time.Duration(c.HttpClientTimeout) * time.Second,
		IdleConnTimeout:       DefaultIdleConnTimeout,
		ExpectContinueTimeout: DefaultExpectContinueTimeout,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   10,
		// MaxConnsPerHost is intentionally left at 0 (unbounded, matching
		// net/http.DefaultTransport). This transport is now cached and reused
		// as a single long-lived *http.Client/*http.Transport by callers (to
		// fix a socket-leak bug where a fresh transport was built per
		// request), so a nonzero MaxConnsPerHost here would become a hard,
		// unqueued-timeout ceiling on concurrent in-flight requests per host
		// for the lifetime of the process -- e.g. `terraform apply
		// -parallelism=25` would silently serialize into batches of N with no
		// bound on how long excess requests wait, since neither this client's
		// Timeout nor its requests' contexts impose one. MaxIdleConns/
		// MaxIdleConnsPerHost above still bound long-term idle-socket
		// retention, which is the resource concern MaxConnsPerHost was
		// presumably added for.
		MaxConnsPerHost: 0,
	}
}

// BuildTransport creates a custom http Transport for authentication to Keyfactor Command API.
func (c *CommandAuthConfig) BuildTransport() (*http.Transport, error) {
	output := c.newHTTPTransport()

	if c.SkipVerify {
		output.TLSClientConfig.InsecureSkipVerify = true
	}

	if c.CommandCACert != "" {
		if _, err := os.Stat(c.CommandCACert); err == nil {
			cert, ioErr := os.ReadFile(c.CommandCACert)
			if ioErr != nil {
				return output, ioErr
			}
			// check if output.TLSClientConfig.RootCAs is nil
			if output.TLSClientConfig.RootCAs == nil {
				output.TLSClientConfig.RootCAs = x509.NewCertPool()
			}
			// Append your custom cert to the pool
			if ok := output.TLSClientConfig.RootCAs.AppendCertsFromPEM(cert); !ok {
				return output, fmt.Errorf("failed to append custom CA cert to pool")
			}
		} else {
			if output.TLSClientConfig.RootCAs == nil {
				output.TLSClientConfig.RootCAs = x509.NewCertPool()
			}
			// Append your custom cert to the pool
			if ok := output.TLSClientConfig.RootCAs.AppendCertsFromPEM([]byte(c.CommandCACert)); !ok {
				return output, fmt.Errorf("failed to append custom CA cert to pool")
			}
		}
	}

	return output, nil
}

// SetClient sets the http Client for authentication to Keyfactor Command API.
func (c *CommandAuthConfig) SetClient(client *http.Client) *http.Client {
	if client != nil {
		c.HttpClient = client
	}
	if c.HttpClient == nil {
		//// Copy the default transport and apply the custom TLS config
		//defaultTransport := http.DefaultTransport.(*http.Transport).Clone()
		////defaultTransport.TLSClientConfig = tlsConfig
		//c.HttpClient = &http.Client{Transport: defaultTransport}
		// Shares its transport construction (and, critically, the fixed
		// IdleConnTimeout/ExpectContinueTimeout/TLSHandshakeTimeout defaults)
		// with BuildTransport() via newHTTPTransport() -- see its doc comment
		// for why those must not scale with HttpClientTimeout.
		c.HttpClient = &http.Client{
			Transport: c.newHTTPTransport(),
		}
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
			// nothing to do
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

	//check if c already has a transport and if it does, update the RootCAs else create a new transport
	if c.HttpClient.Transport != nil {
		if transport, ok := c.HttpClient.Transport.(*http.Transport); ok {
			transport.TLSClientConfig.RootCAs = rootCAs
		} else {
			c.HttpClient.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: rootCAs,
				},
			}
		}
	} else {
		c.HttpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
			},
		}
	}

	// Trust the augmented cert pool in our Client
	//c.HttpClient.Transport = &http.Transport{
	//	TLSClientConfig: &tls.Config{
	//		RootCAs: rootCAs,
	//	},
	//}

	return nil
}

// Authenticate performs the authentication test to Keyfactor Command API and sets Command product version.
func (c *CommandAuthConfig) Authenticate() error {

	if c.HttpClient == nil {
		c.SetClient(nil)
	}

	if c.HttpProtocol == "" {
		c.HttpProtocol = DefaultHttpProtocol
	}
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
		"%s://%s/%s/Status/Endpoints",
		c.HttpProtocol,
		c.CommandHostName,
		//c.CommandPort,
		c.CommandAPIPath,
	)
	log.Printf("[DEBUG] testing auth using endpoint %s ", endPoint)

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
	curlStr, curlErr := RequestToCurl(req)
	if curlErr == nil {
		log.Printf("[TRACE] curl command: %s", curlStr)
	}

	if cErr != nil {
		return cErr
	} else if cResp == nil {
		return fmt.Errorf("failed to authenticate, no response received from Keyfactor Command")
	}

	defer cResp.Body.Close()
	log.Printf("[DEBUG] request to Keyfactor Command API returned status code %d", cResp.StatusCode)

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
	if !c.SkipVerify {
		c.SkipVerify = server.SkipTLSVerify
	}
	if c.HttpClientTimeout <= 0 {
		c.HttpClientTimeout = server.ClientTimeout
	}

	//if !silentLoad {
	//	c.CommandHostName = server.Host
	//	c.CommandPort = server.Port
	//	c.CommandAPIPath = server.APIPath
	//	c.CommandCACert = server.CACertPath
	//	c.SkipVerify = server.SkipTLSVerify
	//} else {
	//	if c.CommandHostName == "" {
	//		c.CommandHostName = server.Host
	//	}
	//	if c.CommandPort <= 0 {
	//		c.CommandPort = server.Port
	//	}
	//	if c.CommandAPIPath == "" {
	//		c.CommandAPIPath = server.APIPath
	//	}
	//	if c.CommandCACert == "" {
	//		c.CommandCACert = server.CACertPath
	//	}
	//	if c.SkipVerify {
	//		c.SkipVerify = server.SkipTLSVerify
	//	}
	//}
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

// GetServerConfig returns the server configuration.
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
	// Never persist a timeout the user never chose. If ValidateAuthConfig
	// synthesized HttpClientTimeout from DefaultClientTimeout because nothing
	// else was configured, leave Server.ClientTimeout at its zero value (and
	// therefore omitted by its `omitempty` JSON/YAML tag) rather than writing
	// out a value that would masquerade as an explicit file-configured
	// setting -- and therefore permanently shadow KEYFACTOR_CLIENT_TIMEOUT --
	// on the next load. See clientTimeoutDefaulted's doc comment.
	if !c.clientTimeoutDefaulted {
		server.ClientTimeout = c.HttpClientTimeout
	}
	return &server
}

type contextKey string

// Example usage of CommandAuthConfig
//
// This example demonstrates how to use CommandAuthConfig to authenticate to the Keyfactor Command API.
//
//	func ExampleCommandAuthConfig_Authenticate() {
//		authConfig := &CommandAuthConfig{
//			ConfigFilePath:   "/path/to/config.json",
//			ConfigProfile:    "default",
//			CommandHostName:  "exampleHost",
//			CommandPort:      443,
//			CommandAPIPath:   "/api/v1",
//			CommandCACert:    "/path/to/ca-cert.pem",
//			SkipVerify:       true,
//			HttpClientTimeout: 60,
//		}
//
//		err := authConfig.Authenticate()
//		if err != nil {
//			fmt.Println("Authentication failed:", err)
//		} else {
//			fmt.Println("Authentication successful")
//		}
//	}

// redactedPlaceholder replaces the value of any sensitive field before a
// request body is rendered into a shareable curl command or written to a
// log. It is intentionally distinctive so it can never be mistaken for real
// data.
const redactedPlaceholder = "***REDACTED***"

// sensitiveBodyKeys is the set of JSON/form field names -- matched
// case-insensitively -- whose values must never be written to a log or a
// generated curl command. This covers the Keyfactor Command API's
// credential-bearing request fields (certificate enrollment/PFX passwords,
// PAM secret values, etc.) as well as common OAuth2 token exchange fields.
//
// "value" is deliberately blanket-redacted rather than only when nested under
// a credential-bearing parent key (e.g. PAM's ProviderTypeParamValues): it is
// how PAM provider creation carries its secret
// (ProviderCreateRequestTypeParamValue.Value), and this redactor walks
// structure generically without tracking which object it's currently inside,
// so a parent-key allowlist would need its own maintenance burden and would
// still miss any future generic-"Value" secret field. "value" as a bare key
// name is not common enough elsewhere in the Command API surface to justify
// that risk, and the surrounding key names (e.g. the parameter name and
// ProviderTypeParamValues itself) remain visible, so little diagnostic value
// is actually lost.
//
// "properties" is deliberately NOT in this set: certificate stores serialize
// their entire (mostly non-secret) Properties map into a single JSON-encoded
// string field, and blanket-redacting it would hide store configuration
// (container names, client machine paths, etc.) that's routinely needed for
// diagnostics. Instead, redactJSONValue re-parses JSON-encoded string values
// (see below) and redacts sensitive keys *within* Properties, preserving the
// rest of its structure.
var sensitiveBodyKeys = map[string]struct{}{
	"password":                {},
	"pfxpassword":             {},
	"keypassword":             {},
	"entrypassword":           {},
	"explicitpassword":        {},
	"authcertificatepassword": {},
	"newpassword":             {},
	"serverpassword":          {},
	"storepassword":           {},
	"relaypassword":           {},
	"passphrase":              {},
	"privatekey":              {},
	"pkcs12blob":              {},
	"secret":                  {},
	"secretvalue":             {},
	"value":                   {},
	"clientsecret":            {},
	"client_secret":           {},
	"accesstoken":             {},
	"access_token":            {},
	"refreshtoken":            {},
	"refresh_token":           {},
	"apikey":                  {},
	"api_key":                 {},
}

// isSensitiveBodyKey reports whether key names a field whose value should be
// redacted before logging, matching case-insensitively.
func isSensitiveBodyKey(key string) bool {
	_, ok := sensitiveBodyKeys[strings.ToLower(key)]
	return ok
}

const (
	// maxNestedJSONStringDepth bounds how many levels of JSON-encoded-string
	// nesting redactJSONValue will unwrap (e.g. a JSON body whose string
	// field is itself a JSON document whose string field is itself JSON,
	// and so on -- exactly how keyfactor-go-client encodes a certificate
	// store's Properties map). This is unrelated to, and does not limit,
	// ordinary object/array nesting depth; it only bounds re-parsing a
	// string value as a fresh JSON document, which is what makes
	// pathological/adversarial nesting expensive. It defends against a body
	// crafted to smuggle a secret past redaction via deep string-in-string
	// nesting.
	maxNestedJSONStringDepth = 6

	// maxNestedJSONStringLen bounds the size of a string value redactJSONValue
	// will attempt to re-parse as nested JSON, so a single request log line
	// can't be forced to do unbounded parsing work on an attacker-controlled
	// multi-megabyte string.
	maxNestedJSONStringLen = 1 << 20 // 1 MiB
)

// redactJSONValue walks a value decoded from JSON (map[string]interface{},
// []interface{}, or a scalar) and returns a copy with the values of any
// sensitive keys replaced by redactedPlaceholder. Structure (object/array
// nesting) is preserved so the rest of the body remains useful for
// diagnostics.
//
// String values that look like a JSON document (e.g. a certificate store's
// Properties field, which keyfactor-go-client marshals into a JSON-encoded
// string rather than a nested object) are recursively re-parsed and redacted
// the same way, up to maxNestedJSONStringDepth levels deep -- otherwise a
// sensitive field nested inside such a string would never be inspected at
// all, since its key name is invisible until the string is parsed.
func redactJSONValue(v interface{}) interface{} {
	return redactJSONValueAtDepth(v, 0)
}

func redactJSONValueAtDepth(v interface{}, nestedStringDepth int) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, vv := range val {
			if isSensitiveBodyKey(k) {
				out[k] = redactedPlaceholder
				continue
			}
			out[k] = redactJSONValueAtDepth(vv, nestedStringDepth)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, vv := range val {
			out[i] = redactJSONValueAtDepth(vv, nestedStringDepth)
		}
		return out
	case string:
		return redactNestedJSONString(val, nestedStringDepth)
	default:
		return val
	}
}

// utf8BOM is the UTF-8 encoding of U+FEFF, the Unicode byte-order mark.
// Files/values authored on Windows (e.g. a PAM/orchestrator service-account
// JSON key embedded in a Properties map value) commonly carry a leading BOM.
const utf8BOM = "\uFEFF"

// stripLeadingBOM removes a leading UTF-8 byte-order-mark from s, if present.
// strings.TrimSpace does not do this: unicode.IsSpace deliberately does not
// treat U+FEFF as whitespace (it's a formatting character, not a space), so a
// BOM-prefixed JSON document survives TrimSpace untouched. Both
// looksLikeJSONDocument's outermost-byte check and redactNestedJSONString's
// actual json.Unmarshal call need the BOM stripped first: encoding/json does
// not tolerate a leading BOM either (json.Valid/json.Unmarshal reject it, not
// silently skip it -- verified empirically), so stripping it explicitly is
// required here, not merely one option among equally-robust choices.
func stripLeadingBOM(s string) string {
	return strings.TrimPrefix(s, utf8BOM)
}

// looksLikeJSONDocument reports whether s is plausibly a JSON object or
// array, based solely on its outermost delimiters. It is intentionally cheap
// and permissive (an unbalanced-but-bracketed string will still attempt to
// parse and fail cleanly in redactNestedJSONString) so that every candidate
// gets a real parse attempt rather than being skipped on a heuristic and
// potentially leaking a secret verbatim. A leading byte-order-mark is
// stripped first -- see stripLeadingBOM -- so a BOM-prefixed JSON document is
// still recognized as JSON rather than silently treated as an opaque string
// and never inspected for nested secrets at all.
func looksLikeJSONDocument(s string) bool {
	t := strings.TrimSpace(stripLeadingBOM(s))
	if len(t) < 2 {
		return false
	}
	return (t[0] == '{' && t[len(t)-1] == '}') || (t[0] == '[' && t[len(t)-1] == ']')
}

// redactNestedJSONString handles a single string value encountered while
// walking a decoded JSON body. Strings that don't look like a JSON document
// are left untouched. Strings that do are re-parsed and redacted like any
// other JSON value and re-serialized -- unless doing so isn't safe (parse
// failure, or the depth/size guards below are hit), in which case the whole
// value is replaced with redactedPlaceholder rather than ever emitting a
// string that looked like it might contain structured secret data.
func redactNestedJSONString(s string, nestedStringDepth int) interface{} {
	if !looksLikeJSONDocument(s) {
		return s
	}

	if nestedStringDepth >= maxNestedJSONStringDepth {
		log.Printf(
			"[WARN] request body redaction: JSON-in-string nesting exceeded max depth %d; redacting the value entirely rather than risk an unredacted secret",
			maxNestedJSONStringDepth,
		)
		return redactedPlaceholder
	}
	if len(s) > maxNestedJSONStringLen {
		log.Printf(
			"[WARN] request body redaction: JSON-in-string value exceeded %d bytes; redacting the value entirely rather than risk an unredacted secret",
			maxNestedJSONStringLen,
		)
		return redactedPlaceholder
	}

	var parsed interface{}
	// encoding/json rejects a leading BOM outright (json.Unmarshal returns an
	// error rather than skipping it), so it must be stripped here too, not
	// just in looksLikeJSONDocument's sniff above -- otherwise every
	// BOM-prefixed value that reaches this point would always fail to parse
	// and fall through to the whole-value redactedPlaceholder branch below,
	// losing the surrounding key names' diagnostic value for no security
	// benefit (the BOM carries no information worth preserving).
	if err := json.Unmarshal([]byte(stripLeadingBOM(s)), &parsed); err != nil {
		// Looks like JSON (balanced outer brackets) but doesn't actually
		// parse -- could be a truncated or malformed secret-bearing
		// fragment. Never emit it raw.
		return redactedPlaceholder
	}

	redacted := redactJSONValueAtDepth(parsed, nestedStringDepth+1)
	out, err := json.Marshal(redacted)
	if err != nil {
		return redactedPlaceholder
	}
	return string(out)
}

// opaqueBodyMarker renders the safe placeholder used whenever a request
// body cannot be confidently classified (and therefore redacted) as JSON or
// form-encoded. It deliberately omits the body content entirely rather than
// guessing, since printing raw bytes here could leak a secret.
func opaqueBodyMarker(contentType string, size int) string {
	ct := contentType
	if ct == "" {
		ct = "unknown"
	}
	return fmt.Sprintf("<redacted: %d bytes, content-type %s>", size, ct)
}

// redactRequestBody renders a safe, loggable representation of an HTTP
// request body for inclusion in a generated curl command. JSON bodies are
// parsed and re-serialized with sensitive values replaced; form-encoded
// bodies (e.g. OAuth2 client_credentials token requests carrying
// client_secret) have sensitive form values replaced. Any body that can't be
// safely classified -- including a body declared as JSON that fails to parse
// -- is omitted entirely behind opaqueBodyMarker rather than risking a raw
// secret leak.
//
// A field name being absent from sensitiveBodyKeys is not by itself proof a
// value is safe to print: the Keyfactor Command API also carries secrets
// inside ordinary JSON string values that are themselves JSON documents
// (e.g. a certificate store's Properties field). redactJSONValue re-parses
// and redacts those recursively (bounded by maxNestedJSONStringDepth/
// maxNestedJSONStringLen) rather than treating a string as an opaque scalar,
// so a sensitive key hidden inside such a string is still found and
// redacted.
func redactRequestBody(contentType string, body []byte) string {
	if len(body) == 0 {
		return ""
	}

	ct := strings.ToLower(contentType)

	switch {
	case strings.Contains(ct, "json"), ct == "" && json.Valid(body):
		var parsed interface{}
		if err := json.Unmarshal(body, &parsed); err != nil {
			log.Printf("[ERROR] failed to parse request body declared as JSON for redaction: %v", err)
			return opaqueBodyMarker(contentType, len(body))
		}
		redacted := redactJSONValue(parsed)
		out, err := json.Marshal(redacted)
		if err != nil {
			log.Printf("[ERROR] failed to marshal redacted request body: %v", err)
			return opaqueBodyMarker(contentType, len(body))
		}
		return string(out)
	case strings.Contains(ct, "www-form-urlencoded"):
		values, err := url.ParseQuery(string(body))
		if err != nil {
			log.Printf("[ERROR] failed to parse form-encoded request body for redaction: %v", err)
			return opaqueBodyMarker(contentType, len(body))
		}
		for k := range values {
			if isSensitiveBodyKey(k) {
				values[k] = []string{redactedPlaceholder}
			}
		}
		return values.Encode()
	default:
		// Unknown/opaque content type: never print raw bytes, since we can't
		// confirm there's no secret buried in them.
		return opaqueBodyMarker(contentType, len(body))
	}
}

func RequestToCurl(req *http.Request) (string, error) {
	var curlCommand strings.Builder

	// Start with the cURL command
	curlCommand.WriteString(fmt.Sprintf("curl -X %s ", req.Method))

	// Add the URL
	curlCommand.WriteString(fmt.Sprintf("%q ", req.URL.String()))

	// Add headers
	for name, values := range req.Header {
		for _, value := range values {
			// check if is Authorization header and skip it
			if strings.EqualFold(name, "Authorization") {
				// check if basic auth and skip it
				if strings.HasPrefix(value, "Basic ") {
					// Remove credentials and put in env variables as placeholder
					log.Printf(
						"[DEBUG] Found Basic auth in Authorization header, " +
							"replacing with env variable references",
					)
					curlCommand.WriteString(
						fmt.Sprintf(
							"-H %q ", fmt.Sprintf(
								"%s: Basic $(echo -n $\"%s,$%s\" | base64)", name,
								EnvKeyfactorUsername, EnvKeyfactorPassword,
							),
						),
					)
					continue
				} else if strings.HasPrefix(value, "Bearer ") {
					// Remove credentials and put in env variables as placeholder
					log.Printf("[DEBUG] Found Bearer token in Authorization header, replacing with kfutil command to fetch token")
					curlCommand.WriteString(
						fmt.Sprintf(
							"-H %q ", fmt.Sprintf(
								"%s: Bearer $(kfutil auth fetch-oauth-token)", name,
							),
						),
					)
					continue
				} else {
					// Skip other Authorization headers
					log.Printf("[ERROR] Skipping unhandled Authorization header: %s", name)
					continue
				}
			}
			curlCommand.WriteString(fmt.Sprintf("-H %q ", fmt.Sprintf("%s: %s", name, value)))
		}
	}

	// Add the body if it exists
	if req.Method == http.MethodPost || req.Method == http.MethodPut {
		if req.Body != nil {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return "", err
			}
			req.Body = io.NopCloser(bytes.NewBuffer(body)) // Restore the request body

			redactedBody := redactRequestBody(req.Header.Get("Content-Type"), body)
			curlCommand.WriteString(fmt.Sprintf("--data %q ", redactedBody))
		}
	}

	return curlCommand.String(), nil
}
