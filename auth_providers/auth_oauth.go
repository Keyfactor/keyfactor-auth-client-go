package auth_providers

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	// DefaultKeyfactorAuthPort is the default port for Keyfactor authentication
	DefaultKeyfactorAuthPort = "8444"

	// DefaultTokenPrefix is the default token prefix for Keyfactor authentication headers
	DefaultTokenPrefix = "Bearer"

	// EnvKeyfactorClientID is the environment variable used to set the Client ID for oauth Client credentials authentication
	EnvKeyfactorClientID = "KEYFACTOR_AUTH_CLIENT_ID"

	// EnvKeyfactorClientSecret is the environment variable used to set the Client secret for oauth Client credentials authentication
	EnvKeyfactorClientSecret = "KEYFACTOR_AUTH_CLIENT_SECRET"

	// EnvKeyfactorAuthTokenURL EnvCommandTokenURL is the environment variable used to set the token URL for oauth Client credentials authentication
	EnvKeyfactorAuthTokenURL = "KEYFACTOR_AUTH_TOKEN_URL"

	// EnvKeyfactorAccessToken is the environment variable used to set the access token for oauth Client credentials authentication
	EnvKeyfactorAccessToken = "KEYFACTOR_AUTH_ACCESS_TOKEN"

	// EnvKeyfactorAuthAudience is the environment variable used to set the audience for oauth Client credentials
	//authentication
	EnvKeyfactorAuthAudience = "KEYFACTOR_AUTH_AUDIENCE"

	// EnvKeyfactorAuthScopes is the environment variable used to set the scopes for oauth Client credentials authentication
	EnvKeyfactorAuthScopes = "KEYFACTOR_AUTH_SCOPES"

	// EnvAuthCACert is a path to a CA certificate for the OAuth Client credentials authentication
	EnvAuthCACert = "KEYFACTOR_AUTH_CA_CERT"
)

var (
	// DefaultScopes is the default scopes for Keyfactor authentication
	DefaultScopes = []string{"openid"}
)

// OAuth Authenticator
var _ Authenticator = &OAuthAuthenticator{}

// OAuthAuthenticator is an Authenticator that uses OAuth2 for authentication.
type OAuthAuthenticator struct {
	Client *http.Client
}

type oauth2Transport struct {
	base http.RoundTripper
	src  oauth2.TokenSource
}

// GetHttpClient returns the http client
func (a *OAuthAuthenticator) GetHttpClient() (*http.Client, error) {
	return a.Client, nil
}

// CommandConfigOauth represents the configuration needed for authentication to Keyfactor Command API using OAuth2.
type CommandConfigOauth struct {
	// CommandAuthConfig is a reference to the base configuration needed for authentication to Keyfactor Command API
	CommandAuthConfig

	// ClientID is the Client ID for OAuth authentication
	ClientID string `json:"client_id,omitempty" yaml:"client_id,omitempty"`

	// ClientSecret is the Client secret for OAuth authentication
	ClientSecret string `json:"client_secret,omitempty" yaml:"client_secret,omitempty"`

	// Audience is the audience for OAuth authentication
	Audience string `json:"audience,omitempty" yaml:"audience,omitempty"`

	// Scopes is the scopes for OAuth authentication
	Scopes []string `json:"scopes,omitempty" yaml:"scopes,omitempty"`

	// CACertificatePath is the path to the CA certificate for OAuth authentication
	CACertificatePath string `json:"idp_ca_cert,omitempty" yaml:"idp_ca_cert,omitempty"`

	// CACertificates is the CA certificates for authentication
	CACertificates []*x509.Certificate `json:"-"`

	// AccessToken is the access token for OAuth authentication
	AccessToken string `json:"access_token,omitempty" yaml:"access_token,omitempty"`

	// RefreshToken is the refresh token for OAuth authentication
	RefreshToken string `json:"refresh_token,omitempty" yaml:"refresh_token,omitempty"`

	// Expiry is the expiry time of the access token
	Expiry time.Time `json:"expiry,omitempty" yaml:"expiry,omitempty"`

	// TokenURL is the token URL for OAuth authentication
	TokenURL string `json:"token_url,omitempty" yaml:"token_url,omitempty"`
}

// NewOAuthAuthenticatorBuilder creates a new CommandConfigOauth instance.
func NewOAuthAuthenticatorBuilder() *CommandConfigOauth {
	return &CommandConfigOauth{}
}

// WithClientId sets the Client ID for OAuth authentication.
func (b *CommandConfigOauth) WithClientId(clientId string) *CommandConfigOauth {
	b.ClientID = clientId
	return b
}

// WithClientSecret sets the Client secret for OAuth authentication.
func (b *CommandConfigOauth) WithClientSecret(clientSecret string) *CommandConfigOauth {
	b.ClientSecret = clientSecret
	return b
}

// WithTokenUrl sets the token URL for OAuth authentication.
func (b *CommandConfigOauth) WithTokenUrl(tokenUrl string) *CommandConfigOauth {
	b.TokenURL = tokenUrl
	return b
}

// WithScopes sets the scopes for OAuth authentication.
func (b *CommandConfigOauth) WithScopes(scopes []string) *CommandConfigOauth {
	b.Scopes = scopes
	return b
}

// WithAudience sets the audience for OAuth authentication.
func (b *CommandConfigOauth) WithAudience(audience string) *CommandConfigOauth {
	b.Audience = audience
	return b
}

// WithCaCertificatePath sets the CA certificate path for OAuth authentication.
func (b *CommandConfigOauth) WithCaCertificatePath(caCertificatePath string) *CommandConfigOauth {
	b.CACertificatePath = caCertificatePath
	return b
}

// WithCaCertificates sets the CA certificates for OAuth authentication.
func (b *CommandConfigOauth) WithCaCertificates(caCertificates []*x509.Certificate) *CommandConfigOauth {
	b.CACertificates = caCertificates
	return b
}

// WithAccessToken sets the access token for OAuth authentication.
func (b *CommandConfigOauth) WithAccessToken(accessToken string) *CommandConfigOauth {
	if accessToken != "" {
		b.AccessToken = accessToken
	}

	return b
}

func (b *CommandConfigOauth) WithHttpClient(httpClient *http.Client) *CommandConfigOauth {
	b.HttpClient = httpClient
	return b
}

// GetHttpClient returns an HTTP client for oAuth authentication.
func (b *CommandConfigOauth) GetHttpClient() (*http.Client, error) {
	cErr := b.ValidateAuthConfig()
	if cErr != nil {
		return nil, cErr
	}

	var client http.Client
	baseTransport, tErr := b.BuildTransport()
	if tErr != nil {
		return nil, tErr
	}

	if b.AccessToken != "" {
		client.Transport = &oauth2.Transport{
			Base: baseTransport,
			Source: oauth2.StaticTokenSource(
				&oauth2.Token{
					AccessToken: b.AccessToken,
					TokenType:   DefaultTokenPrefix,
				},
			),
		}
		return &client, nil
	}

	config := &clientcredentials.Config{
		ClientID:     b.ClientID,
		ClientSecret: b.ClientSecret,
		TokenURL:     b.TokenURL,
		Scopes:       b.Scopes,
	}

	if b.Audience != "" {
		config.EndpointParams = map[string][]string{
			"audience": {b.Audience},
		}
	}

	if len(b.Scopes) == 0 {
		b.Scopes = DefaultScopes
	}

	if b.Audience != "" {
		config.EndpointParams = map[string][]string{
			"Audience": {b.Audience},
		}
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: baseTransport})
	tokenSource := config.TokenSource(ctx)

	client = http.Client{
		Transport: &oauth2Transport{
			base: baseTransport,
			src:  tokenSource,
		},
	}

	return &client, nil
}

// Build creates an OAuth authenticator.
func (b *CommandConfigOauth) Build() (Authenticator, error) {

	client, cErr := b.GetHttpClient()
	if cErr != nil {
		return nil, cErr
	}

	return &OAuthAuthenticator{Client: client}, nil
}

// LoadConfig loads the configuration for Keyfactor Command API using OAuth2.
func (b *CommandConfigOauth) LoadConfig(profile, path string, silentLoad bool) (*Server, error) {
	serverConfig, sErr := b.CommandAuthConfig.LoadConfig(profile, path, silentLoad)
	if sErr != nil {
		if !silentLoad {
			return nil, sErr
		}
		// if silentLoad is true, return nil and nil
		return nil, nil
	}

	if !silentLoad {
		b.ClientID = serverConfig.ClientID
		b.ClientSecret = serverConfig.ClientSecret
		b.TokenURL = serverConfig.OAuthTokenUrl
		b.CACertificatePath = serverConfig.CACertPath

	} else {
		if b.ClientID == "" {
			b.ClientID = serverConfig.ClientID
		}

		if b.ClientSecret == "" {
			b.ClientSecret = serverConfig.ClientSecret
		}

		if b.TokenURL == "" {
			b.TokenURL = serverConfig.OAuthTokenUrl
		}

		//if b.AccessToken == "" {
		//	b.AccessToken = serverConfig.AccessToken
		//}

		if b.Audience == "" {
			b.Audience = serverConfig.Audience
		}

		if b.Scopes == nil || len(b.Scopes) == 0 {
			b.Scopes = serverConfig.Scopes
		}

		if b.CACertificatePath == "" {
			b.CACertificatePath = serverConfig.CACertPath
		}
	}

	return serverConfig, nil
}

// ValidateAuthConfig validates the configuration for Keyfactor Command API using OAuth2.
func (b *CommandConfigOauth) ValidateAuthConfig() error {

	silentLoad := true
	if b.CommandAuthConfig.ConfigProfile != "" {
		silentLoad = false
	} else if b.CommandAuthConfig.ConfigFilePath != "" {
		silentLoad = false
	}

	serverConfig, cErr := b.CommandAuthConfig.LoadConfig(
		b.CommandAuthConfig.ConfigProfile,
		b.CommandAuthConfig.ConfigFilePath,
		silentLoad,
	)

	if !silentLoad && cErr != nil {
		return cErr
	}

	if b.AccessToken == "" {
		// check if access token is set in the environment
		if accessToken, ok := os.LookupEnv(EnvKeyfactorAccessToken); ok {
			b.AccessToken = accessToken
		} else {
			// check if client ID, client secret, and token URL are provided
			if b.ClientID == "" {
				if clientId, idOk := os.LookupEnv(EnvKeyfactorClientID); idOk {
					b.ClientID = clientId
				} else {
					if serverConfig != nil && serverConfig.ClientID != "" {
						b.ClientID = serverConfig.ClientID
					} else {
						return fmt.Errorf("client ID or environment variable %s is required", EnvKeyfactorClientID)
					}
				}
			}

			if b.ClientSecret == "" {
				if clientSecret, sOk := os.LookupEnv(EnvKeyfactorClientSecret); sOk {
					b.ClientSecret = clientSecret
				} else {
					if serverConfig != nil && serverConfig.ClientSecret != "" {
						b.ClientSecret = serverConfig.ClientSecret
					} else {
						return fmt.Errorf(
							"client secret or environment variable %s is required",
							EnvKeyfactorClientSecret,
						)
					}
				}
			}

			if b.TokenURL == "" {
				if tokenUrl, uOk := os.LookupEnv(EnvKeyfactorAuthTokenURL); uOk {
					b.TokenURL = tokenUrl
				} else {
					if serverConfig != nil && serverConfig.OAuthTokenUrl != "" {
						b.TokenURL = serverConfig.OAuthTokenUrl
					} else {
						return fmt.Errorf(
							"token URL or environment variable %s is required",
							EnvKeyfactorAuthTokenURL,
						)
					}
				}
			}
		}
	}

	if b.Audience == "" {
		if audience, ok := os.LookupEnv(EnvKeyfactorAuthAudience); ok {
			b.Audience = audience
		} else {
			if serverConfig != nil && serverConfig.Audience != "" {
				b.Audience = serverConfig.Audience
			}
		}
	}

	if len(b.Scopes) == 0 {
		if scopes, ok := os.LookupEnv(EnvKeyfactorAuthScopes); ok {
			// split the scopes by comma
			b.Scopes = strings.Split(scopes, ",")
		} else {
			if serverConfig != nil && len(serverConfig.Scopes) > 0 {
				b.Scopes = serverConfig.Scopes
			} else {
				b.Scopes = DefaultScopes
			}
		}
	}

	return b.CommandAuthConfig.ValidateAuthConfig()
}

// Authenticate authenticates to Keyfactor Command API using OAuth2.
func (b *CommandConfigOauth) Authenticate() error {

	// validate auth config
	vErr := b.ValidateAuthConfig()
	if vErr != nil {
		return vErr
	}

	// create oauth Client
	oauthy, err := b.GetHttpClient()

	if err != nil {
		return err
	} else if oauthy == nil {
		return fmt.Errorf("unable to create http client")
	}

	b.SetClient(oauthy)
	//b.DefaultHttpClient = oauthy

	aErr := b.CommandAuthConfig.Authenticate()
	if aErr != nil {
		return aErr
	}

	return nil
}

// GetServerConfig returns the server configuration for Keyfactor Command API using OAuth2.
func (b *CommandConfigOauth) GetServerConfig() *Server {
	server := Server{
		Host:          b.CommandHostName,
		Port:          b.CommandPort,
		ClientID:      b.ClientID,
		ClientSecret:  b.ClientSecret,
		AccessToken:   b.AccessToken,
		OAuthTokenUrl: b.TokenURL,
		APIPath:       b.CommandAPIPath,
		Scopes:        b.Scopes,
		Audience:      b.Audience,
		//AuthProvider:  AuthProvider{},
		SkipTLSVerify: b.SkipVerify,
		CACertPath:    b.CommandCACert,
		AuthType:      "oauth",
	}
	return &server
}

// RoundTrip executes a single HTTP transaction, adding the OAuth2 token to the request
func (t *oauth2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.src.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve OAuth token: %w", err)
	}

	// Clone the request to avoid mutating the original
	reqCopy := req.Clone(req.Context())
	token.SetAuthHeader(reqCopy)

	return t.base.RoundTrip(reqCopy)
}
