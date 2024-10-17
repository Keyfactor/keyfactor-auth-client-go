package auth_providers

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
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
	EnvKeyfactorAccessToken = "KEYFACTOR_ACCESS_TOKEN"

	// EnvKeyfactorAuthAudience is the environment variable used to set the audience for oauth Client credentials
	//authentication
	EnvKeyfactorAuthAudience = "KEYFACTOR_AUTH_AUDIENCE"

	// EnvKeyfactorAuthScopes is the environment variable used to set the scopes for oauth Client credentials authentication
	EnvKeyfactorAuthScopes = "KEYFACTOR_AUTH_SCOPES"

	// EnvKeyfactorAuthHostname is the environment variable used to set the hostname for oauth Client credentials authentication
	EnvKeyfactorAuthHostname = "KEYFACTOR_AUTH_HOSTNAME"

	// EnvKeyfactorAuthPort is the environment variable used to set the port for oauth Client credentials authentication
	EnvKeyfactorAuthPort = "KEYFACTOR_AUTH_PORT"

	// EnvAuthCACert is a path to a CA certificate for the OAuth Client credentials authentication
	EnvAuthCACert = "KEYFACTOR_AUTH_CA_CERT"
)

// OAuth Authenticator
var _ Authenticator = &OAuthAuthenticator{}

// OAuthAuthenticator is an Authenticator that uses OAuth2 for authentication.
type OAuthAuthenticator struct {
	Client *http.Client
}

func (a *OAuthAuthenticator) GetHttpClient() (*http.Client, error) {
	return a.Client, nil
}

type CommandConfigOauth struct {
	CommandAuthConfig

	// ClientID is the Client ID for Keycloak authentication
	ClientID string `json:"client_id,omitempty"`

	// ClientSecret is the Client secret for Keycloak authentication
	ClientSecret string `json:"client_secret,omitempty"`

	// Audience is the audience for Keycloak authentication
	Audience string `json:"audience,omitempty"`

	// Scopes is the scopes for Keycloak authentication
	Scopes []string `json:"scopes,omitempty"`

	// CACertificatePath is the path to the CA certificate for Keycloak authentication
	CACertificatePath string `json:"idp_ca_cert,omitempty"`

	// CACertificates is the CA certificates for authentication
	CACertificates []*x509.Certificate `json:"-"`

	// AccessToken is the access token for Keycloak authentication
	AccessToken string `json:"access_token;omitempty"`

	// RefreshToken is the refresh token for Keycloak authentication
	RefreshToken string `json:"refresh_token;omitempty"`

	// Expiry is the expiry time of the access token
	Expiry time.Time `json:"expiry;omitempty"`

	// TokenURL is the token URL for Keycloak authentication
	TokenURL string `json:"token_url"`

	// AuthPort
	AuthPort string `json:"auth_port,omitempty"`

	// AuthType is the type of Keycloak auth to use such as client_credentials, password, etc.
	AuthType string `json:"auth_type,omitempty"`
}

// NewOAuthAuthenticatorBuilder creates a new CommandConfigOauth instance.
func NewOAuthAuthenticatorBuilder() *CommandConfigOauth {
	return &CommandConfigOauth{}
}

// WithClientId sets the Client ID for Keycloak authentication.
func (b *CommandConfigOauth) WithClientId(clientId string) *CommandConfigOauth {
	b.ClientID = clientId
	return b
}

// WithClientSecret sets the Client secret for Keycloak authentication.
func (b *CommandConfigOauth) WithClientSecret(clientSecret string) *CommandConfigOauth {
	b.ClientSecret = clientSecret
	return b
}

// WithTokenUrl sets the token URL for Keycloak authentication.
func (b *CommandConfigOauth) WithTokenUrl(tokenUrl string) *CommandConfigOauth {
	b.TokenURL = tokenUrl
	return b
}

// WithScopes sets the scopes for Keycloak authentication.
func (b *CommandConfigOauth) WithScopes(scopes []string) *CommandConfigOauth {
	b.Scopes = scopes
	return b
}

// WithAudience sets the audience for Keycloak authentication.
func (b *CommandConfigOauth) WithAudience(audience string) *CommandConfigOauth {
	b.Audience = audience
	return b
}

// WithCACertificatePath sets the CA certificate path for Keycloak authentication.
func (b *CommandConfigOauth) WithCaCertificatePath(caCertificatePath string) *CommandConfigOauth {
	b.CACertificatePath = caCertificatePath
	return b
}

// WithCACertificates sets the CA certificates for Keycloak authentication.
func (b *CommandConfigOauth) WithCaCertificates(caCertificates []*x509.Certificate) *CommandConfigOauth {
	b.CACertificates = caCertificates
	return b
}

func (b *CommandConfigOauth) GetHttpClient() (*http.Client, error) {
	//validate the configuration
	cErr := b.ValidateAuthConfig()
	if cErr != nil {
		return nil, cErr
	}

	config := &clientcredentials.Config{
		ClientID:     b.ClientID,
		ClientSecret: b.ClientSecret,
		TokenURL:     b.TokenURL,
		Scopes:       b.Scopes,
	}

	if b.Scopes == nil || len(b.Scopes) == 0 {
		b.Scopes = []string{"openid", "profile", "email"}
	}

	if b.Audience != "" {
		config.EndpointParams = map[string][]string{
			"Audience": {
				b.Audience,
			},
		}
	}

	transport, tErr := b.BuildTransport()
	if tErr != nil {
		return nil, tErr
	}

	tokenSource := config.TokenSource(context.Background())
	oauthTransport := &oauth2.Transport{
		Base:   transport,
		Source: tokenSource,
	}

	return &http.Client{
		Transport: oauthTransport,
	}, nil

}

func (b *CommandConfigOauth) Build() (Authenticator, error) {

	client, cErr := b.GetHttpClient()
	if cErr != nil {
		return nil, cErr
	}

	return &OAuthAuthenticator{Client: client}, nil
}

func (b *CommandConfigOauth) ValidateAuthConfig() error {
	if b.ClientID == "" {
		return fmt.Errorf("Client ID is required")
	}

	if b.ClientSecret == "" {
		return fmt.Errorf("Client secret is required")
	}

	if b.TokenURL == "" {
		return fmt.Errorf("token URL is required")
	}

	//if len(b.Scopes) == 0 {
	//	return fmt.Errorf("at least one scope is required")
	//}

	return b.CommandAuthConfig.ValidateAuthConfig()
}

func (b *CommandConfigOauth) Authenticate() error {

	// validate auth config
	vErr := b.ValidateAuthConfig()
	if vErr != nil {
		return vErr
	}

	// create oauth Client
	oauthy, err := NewOAuthAuthenticatorBuilder().
		WithClientId(b.ClientID).
		WithClientSecret(b.ClientSecret).
		WithTokenUrl(b.TokenURL).
		Build()

	if err != nil {
		return err
	}

	if oauthy != nil {
		oClient, oerr := oauthy.GetHttpClient()
		if oerr != nil {
			return oerr
		}
		b.SetClient(oClient)
	}

	aErr := b.CommandAuthConfig.Authenticate()
	if aErr != nil {
		return aErr
	}

	return nil
}
