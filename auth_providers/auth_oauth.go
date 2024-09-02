package auth_providers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type Authenticator interface {
	GetHttpClient() (*http.Client, error)
}

// OAuth Authenticator

var _ Authenticator = &OAuthAuthenticator{}

// OAuthAuthenticator is an Authenticator that uses OAuth2 for authentication.
type OAuthAuthenticator struct {
	client *http.Client
}

type OAuthAuthenticatorBuilder struct {
	clientId          string
	clientSecret      string
	tokenUrl          string
	audience          string
	scopes            []string
	caCertificatePath string
	caCertificates    []*x509.Certificate
}

func NewOAuthAuthenticatorBuilder() *OAuthAuthenticatorBuilder {
	return &OAuthAuthenticatorBuilder{}
}

func (b *OAuthAuthenticatorBuilder) WithClientId(clientId string) *OAuthAuthenticatorBuilder {
	b.clientId = clientId
	return b
}

func (b *OAuthAuthenticatorBuilder) WithClientSecret(clientSecret string) *OAuthAuthenticatorBuilder {
	b.clientSecret = clientSecret
	return b
}

func (b *OAuthAuthenticatorBuilder) WithTokenUrl(tokenUrl string) *OAuthAuthenticatorBuilder {
	b.tokenUrl = tokenUrl
	return b
}

func (b *OAuthAuthenticatorBuilder) WithScopes(scopes []string) *OAuthAuthenticatorBuilder {
	b.scopes = scopes
	return b
}

func (b *OAuthAuthenticatorBuilder) WithAudience(audience string) *OAuthAuthenticatorBuilder {
	b.audience = audience
	return b
}

func (b *OAuthAuthenticatorBuilder) WithCaCertificatePath(caCertificatePath string) *OAuthAuthenticatorBuilder {
	b.caCertificatePath = caCertificatePath
	return b
}

func (b *OAuthAuthenticatorBuilder) WithCaCertificates(caCertificates []*x509.Certificate) *OAuthAuthenticatorBuilder {
	b.caCertificates = caCertificates
	return b
}

func (b *OAuthAuthenticatorBuilder) Build() (Authenticator, error) {
	config := &clientcredentials.Config{
		ClientID:     b.clientId,
		ClientSecret: b.clientSecret,
		TokenURL:     b.tokenUrl,
		Scopes:       b.scopes,
	}

	if b.audience != "" {
		config.EndpointParams = map[string][]string{
			"audience": {
				b.audience,
			},
		}
	}

	tokenSource := config.TokenSource(context.Background())
	oauthTransport := &oauth2.Transport{
		Base:   http.DefaultTransport,
		Source: tokenSource,
	}

	if b.caCertificates == nil {
		var err error
		b.caCertificates, err = findCaCertificate(b.caCertificatePath)
		if err != nil {
			return nil, fmt.Errorf("failed to find CA certificates: %w", err)
		}
	}

	if len(b.caCertificates) > 0 {
		tlsConfig := &tls.Config{
			Renegotiation: tls.RenegotiateOnceAsClient,
		}

		tlsConfig.RootCAs = x509.NewCertPool()
		for _, caCert := range b.caCertificates {
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

func (a *OAuthAuthenticator) GetHttpClient() (*http.Client, error) {
	return a.client, nil
}

func findCaCertificate(caCertificatePath string) ([]*x509.Certificate, error) {
	if caCertificatePath == "" {
		return nil, nil
	}

	buf, err := os.ReadFile(caCertificatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate file at path %s: %w", caCertificatePath, err)
	}
	// Decode the PEM encoded certificates into a slice of PEM blocks
	chainBlocks, _, err := decodePEMBytes(buf)
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

func decodePEMBytes(buf []byte) ([]*pem.Block, []byte, error) {
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
