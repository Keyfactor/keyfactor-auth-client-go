package auth_providers

import (
	"context"
	"crypto/tls"
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

	// EnvKeyfactorClientID is the environment variable used to set the client ID for oauth client credentials authentication
	EnvKeyfactorClientID = "KEYFACTOR_AUTH_CLIENT_ID"

	// EnvKeyfactorClientSecret is the environment variable used to set the client secret for oauth client credentials authentication
	EnvKeyfactorClientSecret = "KEYFACTOR_AUTH_CLIENT_SECRET"

	// EnvKeyfactorAuthTokenURL EnvCommandTokenURL is the environment variable used to set the token URL for oauth client credentials authentication
	EnvKeyfactorAuthTokenURL = "KEYFACTOR_AUTH_TOKEN_URL"

	// EnvKeyfactorAccessToken is the environment variable used to set the access token for oauth client credentials authentication
	EnvKeyfactorAccessToken = "KEYFACTOR_ACCESS_TOKEN"

	// EnvKeyfactorAuthAudience is the environment variable used to set the audience for oauth client credentials
	//authentication
	EnvKeyfactorAuthAudience = "KEYFACTOR_AUTH_AUDIENCE"

	// EnvKeyfactorAuthScopes is the environment variable used to set the scopes for oauth client credentials authentication
	EnvKeyfactorAuthScopes = "KEYFACTOR_AUTH_SCOPES"

	// EnvKeyfactorAuthHostname is the environment variable used to set the hostname for oauth client credentials authentication
	EnvKeyfactorAuthHostname = "KEYFACTOR_AUTH_HOSTNAME"

	// EnvKeyfactorAuthPort is the environment variable used to set the port for oauth client credentials authentication
	EnvKeyfactorAuthPort = "KEYFACTOR_AUTH_PORT"

	// EnvAuthCACert is a path to a CA certificate for the OAuth client credentials authentication
	EnvAuthCACert = "KEYFACTOR_AUTH_CA_CERT"
)

// OAuth Authenticator
var _ Authenticator = &OAuthAuthenticator{}

// OAuthAuthenticator is an Authenticator that uses OAuth2 for authentication.
type OAuthAuthenticator struct {
	client *http.Client
}

func (a *OAuthAuthenticator) GetHttpClient() (*http.Client, error) {
	return a.client, nil
}

type CommandConfigOauth struct {
	CommandAuthConfig
	ClientID          string              `json:"client_id,omitempty"`
	ClientSecret      string              `json:"client_secret,omitempty"`
	TokenURL          string              `json:"token_url,omitempty"`
	Audience          string              `json:"audience,omitempty"`
	Scopes            []string            `json:"scopes,omitempty"`
	CACertificatePath string              `json:"idp_ca_cert_path,omitempty"`
	CACertificates    []*x509.Certificate `json:"-"`
}

func NewOAuthAuthenticatorBuilder() *CommandConfigOauth {
	return &CommandConfigOauth{}
}

func (b *CommandConfigOauth) WithClientId(clientId string) *CommandConfigOauth {
	b.ClientID = clientId
	return b
}

func (b *CommandConfigOauth) WithClientSecret(clientSecret string) *CommandConfigOauth {
	b.ClientSecret = clientSecret
	return b
}

func (b *CommandConfigOauth) WithTokenUrl(tokenUrl string) *CommandConfigOauth {
	b.TokenURL = tokenUrl
	return b
}

func (b *CommandConfigOauth) WithScopes(scopes []string) *CommandConfigOauth {
	b.Scopes = scopes
	return b
}

func (b *CommandConfigOauth) WithAudience(audience string) *CommandConfigOauth {
	b.Audience = audience
	return b
}

func (b *CommandConfigOauth) WithCaCertificatePath(caCertificatePath string) *CommandConfigOauth {
	b.CACertificatePath = caCertificatePath
	return b
}

func (b *CommandConfigOauth) WithCaCertificates(caCertificates []*x509.Certificate) *CommandConfigOauth {
	b.CACertificates = caCertificates
	return b
}

func (b *CommandConfigOauth) Build() (Authenticator, error) {
	config := &clientcredentials.Config{
		ClientID:     b.ClientID,
		ClientSecret: b.ClientSecret,
		TokenURL:     b.TokenURL,
		Scopes:       b.Scopes,
	}

	if b.Audience != "" {
		config.EndpointParams = map[string][]string{
			"Audience": {
				b.Audience,
			},
		}
	}

	tokenSource := config.TokenSource(context.Background())
	oauthTransport := &oauth2.Transport{
		Base:   http.DefaultTransport,
		Source: tokenSource,
	}

	if b.CACertificates == nil {
		var err error
		b.CACertificates, err = FindCACertificate(b.CACertificatePath)
		if err != nil {
			return nil, fmt.Errorf("failed to find CA certificates: %w", err)
		}
	}

	if len(b.CACertificates) > 0 {
		tlsConfig := &tls.Config{
			Renegotiation: tls.RenegotiateOnceAsClient,
		}

		tlsConfig.RootCAs = x509.NewCertPool()
		for _, caCert := range b.CACertificates {
			tlsConfig.RootCAs.AddCert(caCert)
		}

		customTransport := http.DefaultTransport.(*http.Transport).Clone()
		customTransport.TLSClientConfig = tlsConfig
		customTransport.TLSHandshakeTimeout = 10 * time.Second

		// Wrap the custom transport with the oauth2.Transport
		oauthTransport.Base = customTransport
	}

	client := &http.Client{
		Transport: oauthTransport,
	}

	return &OAuthAuthenticator{client: client}, nil
}

func (b *CommandConfigOauth) ValidateAuthConfig() error {
	if b.ClientID == "" {
		return fmt.Errorf("client ID is required")
	}

	if b.ClientSecret == "" {
		return fmt.Errorf("client secret is required")
	}

	if b.TokenURL == "" {
		return fmt.Errorf("token URL is required")
	}

	if len(b.Scopes) == 0 {
		return fmt.Errorf("at least one scope is required")
	}

	return b.CommandAuthConfig.ValidateAuthConfig()
}

func (b *CommandConfigOauth) Authenticate() error {

	// validate auth config
	vErr := b.ValidateAuthConfig()
	if vErr != nil {
		return vErr
	}

	// create oauth client
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
