// Copyright 2026 Keyfactor
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
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

const (
	// EnvKeyfactorKrbUsername is the environment variable for the Kerberos principal
	EnvKeyfactorKrbUsername = "KEYFACTOR_AUTH_KRB_USERNAME"

	// EnvKeyfactorKrbPassword is the environment variable for the Kerberos password
	EnvKeyfactorKrbPassword = "KEYFACTOR_AUTH_KRB_PASSWORD"

	// EnvKeyfactorKrbRealm is the environment variable for the Kerberos realm
	EnvKeyfactorKrbRealm = "KEYFACTOR_AUTH_KRB_REALM"

	// EnvKeyfactorKrbKeytab is the environment variable for the Kerberos keytab file path
	EnvKeyfactorKrbKeytab = "KEYFACTOR_AUTH_KRB_KEYTAB"

	// EnvKeyfactorKrbConfig is the environment variable for the krb5.conf file path
	EnvKeyfactorKrbConfig = "KEYFACTOR_AUTH_KRB_CONFIG"

	// EnvKeyfactorKrbCCache is the environment variable for the Kerberos credential cache path
	EnvKeyfactorKrbCCache = "KEYFACTOR_AUTH_KRB_CCACHE"

	// EnvKeyfactorKrbSPN is the environment variable for the Service Principal Name
	EnvKeyfactorKrbSPN = "KEYFACTOR_AUTH_KRB_SPN"

	// EnvKeyfactorKrbDisablePAFXFast is the environment variable to disable PA-FX-FAST for AD compatibility
	EnvKeyfactorKrbDisablePAFXFast = "KEYFACTOR_AUTH_KRB_DISABLE_PAFXFAST"

	// DefaultKrbConfigPath is the default path to krb5.conf
	DefaultKrbConfigPath = "/etc/krb5.conf"
)

// Kerberos Authenticator
var _ Authenticator = &KerberosAuthenticator{}

// KerberosAuthenticator is an Authenticator that uses Kerberos/SPNEGO for authentication.
type KerberosAuthenticator struct {
	Client *http.Client
}

// GetHttpClient returns the http client
func (k *KerberosAuthenticator) GetHttpClient() (*http.Client, error) {
	return k.Client, nil
}

// CommandAuthConfigKerberos represents the configuration needed for Kerberos authentication to Keyfactor Command API.
type CommandAuthConfigKerberos struct {
	// CommandAuthConfig is a reference to the base configuration needed for authentication to Keyfactor Command API
	CommandAuthConfig

	// Username is the Kerberos principal (user@REALM or just username)
	Username string `json:"username,omitempty" yaml:"username,omitempty"`

	// Password is the password for password-based Kerberos authentication
	Password string `json:"password,omitempty" yaml:"password,omitempty"`

	// Realm is the Kerberos realm (uppercase, e.g., EXAMPLE.COM)
	Realm string `json:"kerberos_realm,omitempty" yaml:"kerberos_realm,omitempty"`

	// KeytabPath is the path to the keytab file for keytab-based authentication
	KeytabPath string `json:"kerberos_keytab,omitempty" yaml:"kerberos_keytab,omitempty"`

	// ConfigPath is the path to krb5.conf (default: /etc/krb5.conf)
	ConfigPath string `json:"kerberos_config,omitempty" yaml:"kerberos_config,omitempty"`

	// CCachePath is the path to the Kerberos credential cache
	CCachePath string `json:"kerberos_ccache,omitempty" yaml:"kerberos_ccache,omitempty"`

	// SPN is the Service Principal Name (optional, auto-generated from host as HTTP/hostname)
	SPN string `json:"kerberos_spn,omitempty" yaml:"kerberos_spn,omitempty"`

	// DisablePAFXFast disables PA-FX-FAST for Active Directory compatibility
	DisablePAFXFast bool `json:"kerberos_disable_pafxfast,omitempty" yaml:"kerberos_disable_pafxfast,omitempty"`
}

// NewKerberosAuthenticatorBuilder creates a new instance of CommandAuthConfigKerberos
func NewKerberosAuthenticatorBuilder() *CommandAuthConfigKerberos {
	return &CommandAuthConfigKerberos{}
}

// WithUsername sets the Kerberos principal for authentication
func (k *CommandAuthConfigKerberos) WithUsername(username string) *CommandAuthConfigKerberos {
	k.Username = username
	return k
}

// WithPassword sets the password for password-based Kerberos authentication
func (k *CommandAuthConfigKerberos) WithPassword(password string) *CommandAuthConfigKerberos {
	k.Password = password
	return k
}

// WithRealm sets the Kerberos realm
func (k *CommandAuthConfigKerberos) WithRealm(realm string) *CommandAuthConfigKerberos {
	k.Realm = strings.ToUpper(realm)
	return k
}

// WithKeytabPath sets the keytab file path for keytab-based authentication
func (k *CommandAuthConfigKerberos) WithKeytabPath(keytabPath string) *CommandAuthConfigKerberos {
	k.KeytabPath = keytabPath
	return k
}

// WithConfigPath sets the krb5.conf file path
func (k *CommandAuthConfigKerberos) WithConfigPath(configPath string) *CommandAuthConfigKerberos {
	k.ConfigPath = configPath
	return k
}

// WithCCachePath sets the credential cache path for ccache-based authentication
func (k *CommandAuthConfigKerberos) WithCCachePath(ccachePath string) *CommandAuthConfigKerberos {
	k.CCachePath = ccachePath
	return k
}

// WithSPN sets the Service Principal Name
func (k *CommandAuthConfigKerberos) WithSPN(spn string) *CommandAuthConfigKerberos {
	k.SPN = spn
	return k
}

// WithDisablePAFXFast sets whether to disable PA-FX-FAST for AD compatibility
func (k *CommandAuthConfigKerberos) WithDisablePAFXFast(disable bool) *CommandAuthConfigKerberos {
	k.DisablePAFXFast = disable
	return k
}

// spnegoTransport wraps an http.RoundTripper to add SPNEGO/Kerberos authentication
type spnegoTransport struct {
	base      http.RoundTripper
	krbClient *client.Client
	spn       string
}

// RoundTrip implements http.RoundTripper and adds SPNEGO authentication headers
func (t *spnegoTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Determine SPN - if not provided, generate from request host
	spnToUse := t.spn
	if spnToUse == "" {
		spnToUse = "HTTP/" + req.URL.Hostname()
	}

	// Set the SPNEGO header on the request
	if err := spnego.SetSPNEGOHeader(t.krbClient, req, spnToUse); err != nil {
		return nil, fmt.Errorf("failed to set SPNEGO header: %w", err)
	}

	// Forward the request to the actual transport
	return t.base.RoundTrip(req)
}

// GetHttpClient returns the http client configured with Kerberos/SPNEGO authentication
func (k *CommandAuthConfigKerberos) GetHttpClient() (*http.Client, error) {
	// Validate the configuration
	cErr := k.ValidateAuthConfig()
	if cErr != nil {
		return nil, cErr
	}

	// Load krb5.conf
	cfg, err := config.Load(k.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load Kerberos config from %s: %w", k.ConfigPath, err)
	}

	// Create Kerberos client based on authentication method
	var krbClient *client.Client

	// Settings for AD compatibility
	var settings []func(*client.Settings)
	if k.DisablePAFXFast {
		settings = append(settings, client.DisablePAFXFAST(true))
	}

	switch {
	case k.CCachePath != "":
		// Use credential cache
		cc, ccErr := credentials.LoadCCache(k.CCachePath)
		if ccErr != nil {
			return nil, fmt.Errorf("failed to load credential cache from %s: %w", k.CCachePath, ccErr)
		}
		krbClient, err = client.NewFromCCache(cc, cfg, settings...)
		if err != nil {
			return nil, fmt.Errorf("failed to create Kerberos client from credential cache: %w", err)
		}

	case k.KeytabPath != "":
		// Use keytab file
		kt, ktErr := keytab.Load(k.KeytabPath)
		if ktErr != nil {
			return nil, fmt.Errorf("failed to load keytab from %s: %w", k.KeytabPath, ktErr)
		}
		krbClient = client.NewWithKeytab(k.Username, k.Realm, kt, cfg, settings...)

	default:
		// Use password authentication
		krbClient = client.NewWithPassword(k.Username, k.Realm, k.Password, cfg, settings...)
	}

	// Login to get TGT (not needed for ccache)
	if k.CCachePath == "" {
		loginErr := krbClient.Login()
		if loginErr != nil {
			return nil, fmt.Errorf("failed to login to Kerberos: %w", loginErr)
		}
	}

	// Build base transport with TLS config
	transport, tErr := k.CommandAuthConfig.BuildTransport()
	if tErr != nil {
		return nil, tErr
	}

	// Wrap transport with SPNEGO authentication
	return &http.Client{
		Transport: &spnegoTransport{
			base:      transport,
			krbClient: krbClient,
			spn:       k.SPN,
		},
	}, nil
}

// Build creates a new instance of KerberosAuthenticator
func (k *CommandAuthConfigKerberos) Build() (Authenticator, error) {
	client, cErr := k.GetHttpClient()
	if cErr != nil {
		return nil, cErr
	}
	k.HttpClient = client

	return &KerberosAuthenticator{Client: client}, nil
}

// ValidateAuthConfig validates the Kerberos authentication configuration.
func (k *CommandAuthConfigKerberos) ValidateAuthConfig() error {
	silentLoad := true
	if k.CommandAuthConfig.ConfigProfile != "" {
		silentLoad = false
	} else if k.CommandAuthConfig.ConfigFilePath != "" {
		silentLoad = false
	}
	serverConfig, cErr := k.CommandAuthConfig.LoadConfig(
		k.CommandAuthConfig.ConfigProfile,
		k.CommandAuthConfig.ConfigFilePath,
		silentLoad,
	)
	if !silentLoad && cErr != nil {
		return cErr
	}

	// Load ConfigPath (krb5.conf)
	if k.ConfigPath == "" {
		if configPath, ok := os.LookupEnv(EnvKeyfactorKrbConfig); ok {
			k.ConfigPath = configPath
		} else if serverConfig != nil && serverConfig.KerberosConfig != "" {
			k.ConfigPath = serverConfig.KerberosConfig
		} else {
			k.ConfigPath = DefaultKrbConfigPath
		}
	}

	// Check if krb5.conf exists
	if _, err := os.Stat(k.ConfigPath); os.IsNotExist(err) {
		return fmt.Errorf("Kerberos config file not found at %s", k.ConfigPath)
	}

	// Load CCachePath
	if k.CCachePath == "" {
		if ccachePath, ok := os.LookupEnv(EnvKeyfactorKrbCCache); ok {
			k.CCachePath = ccachePath
		} else if serverConfig != nil && serverConfig.KerberosCCache != "" {
			k.CCachePath = serverConfig.KerberosCCache
		}
	}

	// Load KeytabPath
	if k.KeytabPath == "" {
		if keytabPath, ok := os.LookupEnv(EnvKeyfactorKrbKeytab); ok {
			k.KeytabPath = keytabPath
		} else if serverConfig != nil && serverConfig.KerberosKeytab != "" {
			k.KeytabPath = serverConfig.KerberosKeytab
		}
	}

	// Validate authentication method - need at least one of: ccache, keytab, or username/password
	hasCCache := k.CCachePath != "" && fileExists(k.CCachePath)
	hasKeytab := k.KeytabPath != "" && fileExists(k.KeytabPath)

	if !hasCCache && !hasKeytab {
		// Need username and password for password auth
		if k.Username == "" {
			if username, ok := os.LookupEnv(EnvKeyfactorKrbUsername); ok {
				k.Username = username
			} else if serverConfig != nil && serverConfig.Username != "" {
				k.Username = serverConfig.Username
			} else {
				return fmt.Errorf(
					"Kerberos authentication requires one of: credential cache (%s), keytab (%s), or username (%s)",
					EnvKeyfactorKrbCCache, EnvKeyfactorKrbKeytab, EnvKeyfactorKrbUsername,
				)
			}
		}

		if k.Password == "" {
			if password, ok := os.LookupEnv(EnvKeyfactorKrbPassword); ok {
				k.Password = password
			} else if serverConfig != nil && serverConfig.Password != "" {
				k.Password = serverConfig.Password
			} else {
				return fmt.Errorf(
					"password or environment variable %s is required for password-based Kerberos authentication",
					EnvKeyfactorKrbPassword,
				)
			}
		}
	}

	// If using keytab, we need username
	if hasKeytab && k.Username == "" {
		if username, ok := os.LookupEnv(EnvKeyfactorKrbUsername); ok {
			k.Username = username
		} else if serverConfig != nil && serverConfig.Username != "" {
			k.Username = serverConfig.Username
		} else {
			return fmt.Errorf(
				"username or environment variable %s is required for keytab-based Kerberos authentication",
				EnvKeyfactorKrbUsername,
			)
		}
	}

	// Parse realm from username if included (user@REALM format)
	k.parseUsernameRealm()

	// Load Realm
	if k.Realm == "" {
		if realm, ok := os.LookupEnv(EnvKeyfactorKrbRealm); ok {
			k.Realm = strings.ToUpper(realm)
		} else if serverConfig != nil && serverConfig.KerberosRealm != "" {
			k.Realm = strings.ToUpper(serverConfig.KerberosRealm)
		}
	}

	// Realm is required for keytab and password auth (not for ccache)
	if !hasCCache && k.Realm == "" {
		return fmt.Errorf("Kerberos realm or environment variable %s is required", EnvKeyfactorKrbRealm)
	}

	// Load SPN
	if k.SPN == "" {
		if spn, ok := os.LookupEnv(EnvKeyfactorKrbSPN); ok {
			k.SPN = spn
		} else if serverConfig != nil && serverConfig.KerberosSPN != "" {
			k.SPN = serverConfig.KerberosSPN
		}
		// SPN is optional - spnego.NewClient will auto-generate from host if empty
	}

	// Load DisablePAFXFast
	if !k.DisablePAFXFast {
		if disable, ok := os.LookupEnv(EnvKeyfactorKrbDisablePAFXFast); ok {
			k.DisablePAFXFast = disable == "true" || disable == "1"
		}
	}

	return k.CommandAuthConfig.ValidateAuthConfig()
}

// Authenticate authenticates the request using Kerberos/SPNEGO authentication.
func (k *CommandAuthConfigKerberos) Authenticate() error {
	cErr := k.ValidateAuthConfig()
	if cErr != nil {
		return cErr
	}

	// Create Kerberos Client
	authy, err := k.Build()
	if err != nil {
		return err
	}

	if authy != nil {
		kClient, kerr := authy.GetHttpClient()
		if kerr != nil {
			return kerr
		}
		k.SetClient(kClient)
	}

	return k.CommandAuthConfig.Authenticate()
}

// parseUsernameRealm parses the username to extract the realm if it's included in the username.
// It supports the format: "username@REALM"
func (k *CommandAuthConfigKerberos) parseUsernameRealm() {
	if strings.Contains(k.Username, "@") {
		parts := strings.Split(k.Username, "@")
		if len(parts) == 2 {
			k.Username = parts[0]
			if k.Realm == "" {
				k.Realm = strings.ToUpper(parts[1])
			}
		}
	}
}

// GetServerConfig returns the server configuration
func (k *CommandAuthConfigKerberos) GetServerConfig() *Server {
	server := Server{
		Host:           k.CommandHostName,
		Port:           k.CommandPort,
		Username:       k.Username,
		Password:       k.Password,
		APIPath:        k.CommandAPIPath,
		SkipTLSVerify:  k.SkipVerify,
		CACertPath:     k.CommandCACert,
		AuthType:       "kerberos",
		KerberosRealm:  k.Realm,
		KerberosKeytab: k.KeytabPath,
		KerberosConfig: k.ConfigPath,
		KerberosCCache: k.CCachePath,
		KerberosSPN:    k.SPN,
	}
	return &server
}

// fileExists checks if a file exists at the given path
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
