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
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
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
	DefaultScopes []string
)

var (
	ErrMissingClientCredentials = fmt.Errorf("client ID, client secret, and token URL are required if access token or static token source is not provided. Please provide these values directly or populate environment variables %s, %s, and %s", EnvKeyfactorClientID, EnvKeyfactorClientSecret, EnvKeyfactorAuthTokenURL)
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

// oauthTokenFetchContext returns a context carrying an oauth2.HTTPClient
// value pointing at an *http.Client that wraps baseTransport with a bounded
// Timeout derived from httpClientTimeout, AND an overall deadline on the
// returned context itself (via context.WithTimeout) bounding the same
// duration. Every call site that hands a context to the golang.org/x/oauth2
// machinery for a token fetch MUST use this helper instead of
// context.Background(): golang.org/x/oauth2/internal.ContextClient falls
// back to http.DefaultClient (Timeout: 0, unbounded) whenever the context
// carries no oauth2.HTTPClient value, and net/http.DefaultTransport sets no
// ResponseHeaderTimeout -- so a TCP connection that succeeds and then a
// hung/overloaded token endpoint simply never responds hangs the caller
// forever, regardless of HttpClientTimeout.
//
// The context-level deadline (not just the http.Client.Timeout field) is
// required because golang.org/x/oauth2/internal.RetrieveToken silently
// performs up to TWO sequential HTTP round trips for a single logical token
// fetch: on the first-ever call to a given tokenURL/clientID pair it doesn't
// yet know whether the server wants client credentials sent as
// AuthStyleInHeader or AuthStyleInParams, so it tries the first style and,
// if that attempt fails for ANY reason (including a timeout), immediately
// retries with the other style using the exact same ctx. http.Client.Do()
// re-derives its deadline as time.Now().Add(c.Timeout) fresh on every call,
// so relying on the *http.Client.Timeout field alone gives each of those two
// sequential attempts its own full httpClientTimeout budget -- silently
// doubling the observed worst-case wall-clock cost of a hard failure (a
// black-holed/unroutable token endpoint) to ~2x httpClientTimeout, per
// attempt further capped at DefaultDialTimeout during the dial phase
// specifically. (An httpClientTimeout of 15s measured as *exactly* 30s in
// the wild against such an endpoint -- 2x15 -- which happens to equal
// DefaultDialTimeout and is easy to misdiagnose as a dial-timeout bug; it
// is not, the 30s was coincidental.) A context-level deadline fixes this
// because it is an absolute point in time set once, shared by both
// sequential attempts: the first attempt consumes some (or all) of the
// budget, and http.Client.Do()'s own per-call deadline computation always
// defers to an earlier deadline already present on the request's context
// (see net/http's setRequestCancel/timeBeforeContextDeadline), so the
// second attempt is bounded by whatever budget is actually left -- zero, if
// the first attempt already exhausted it -- rather than getting a fresh
// full window.
//
// This context must NOT be cached and reused across multiple logical token
// fetches spread out over time (e.g. an oauth2 token source that refreshes
// hours after it was constructed): its deadline is relative to the moment
// this function is called, so a stale cached instance would eventually
// make every future refresh fail instantly with "context deadline
// exceeded" regardless of network conditions. Every call site must invoke
// this function fresh for each logical fetch and must call the returned
// CancelFunc once that fetch completes to release the timer promptly (see
// boundedClientCredentialsTokenSource for how GetHttpClient()'s
// long-lived, cached token source still gets a fresh context per actual
// refresh).
//
// Guards against httpClientTimeout <= 0 (ValidateAuthConfig should already
// guarantee a positive value by the time callers reach this point, but
// http.Client.Timeout: 0 means "no timeout," so an unguarded fallthrough here
// would silently reintroduce the exact same unbounded-wait hazard in a new
// place).
func oauthTokenFetchContext(baseTransport http.RoundTripper, httpClientTimeout int) (context.Context, context.CancelFunc) {
	tokenFetchTimeoutSeconds := httpClientTimeout
	if tokenFetchTimeoutSeconds <= 0 {
		tokenFetchTimeoutSeconds = DefaultClientTimeout
	}
	timeout := time.Duration(tokenFetchTimeoutSeconds) * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Transport: baseTransport, Timeout: timeout})
	return ctx, cancel
}

// boundedClientCredentialsTokenSource wraps a *clientcredentials.Config so
// that EVERY actual token fetch -- not just the first -- gets a freshly
// bounded context/http.Client pair from oauthTokenFetchContext, rather than
// the single ctx/http.Client that clientcredentials.Config.TokenSource would
// otherwise capture once (at GetHttpClient() call time) and reuse forever.
//
// This matters for two independent reasons:
//  1. oauthTokenFetchContext's returned context now carries an absolute
//     deadline (see its doc comment) that must not be reused past the
//     logical fetch it was created for, or every future token refresh would
//     fail instantly once that original deadline has passed.
//  2. Building the context fresh on every actual refresh, rather than once
//     up front, is also simply correct: it is oauth2.ReuseTokenSource (see
//     GetHttpClient) that decides when a real network fetch is even
//     necessary, by checking the cached token's validity first. This type
//     is only ever asked for a new Token() when a real fetch is required.
type boundedClientCredentialsTokenSource struct {
	config            *clientcredentials.Config
	baseTransport     http.RoundTripper
	httpClientTimeout int
}

// Token performs a single, freshly-bounded client_credentials token fetch.
func (s *boundedClientCredentialsTokenSource) Token() (*oauth2.Token, error) {
	ctx, cancel := oauthTokenFetchContext(s.baseTransport, s.httpClientTimeout)
	defer cancel()
	return s.config.Token(ctx)
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

	// ExternalTokenSource, when set, supplies access token from a caller-provided
	// oauth2.TokenSource instead of any credential-based flow this SDK manages itself.
	// Intended for ambient / workload identity credential providers where the caller
	// already has a token-producing mechanism
	ExternalTokenSource oauth2.TokenSource `json:"-" yaml:"-"`

	// unexported: lazily initialized, shared across GetHttpClient() calls
	tokenSource oauth2.TokenSource
	tsMu        sync.Mutex
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

func (b *CommandConfigOauth) WithExternalTokenSource(src oauth2.TokenSource) *CommandConfigOauth {
	b.ExternalTokenSource = src
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

	// If an access token is provided directly, use it for the HTTP client instead of fetching a new one.
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

	// The client_credentials token fetch is NOT bounded by baseTransport's
	// ResponseHeaderTimeout/TLSHandshakeTimeout in any useful way here, and
	// must not rely on a single ctx/http.Client captured once and reused for
	// every future token refresh: see boundedClientCredentialsTokenSource's
	// and oauthTokenFetchContext's doc comments for why a fresh bounded
	// context is built for every actual refresh instead, and why that
	// context must carry its own deadline rather than relying solely on the
	// wrapped http.Client's Timeout field.
	//
	// Lazily initialize the token source and cache it. oauth2.ReuseTokenSource
	// caches the resulting token and only calls back into
	// boundedClientCredentialsTokenSource.Token() when a real network fetch
	// is actually required (initial fetch, or refresh after expiry).
	b.tsMu.Lock()
	if b.tokenSource == nil {
		if b.ExternalTokenSource != nil {
			// Use the caller-supplied external token source, wrapping it with a buffer to ensure tokens are refreshed slightly before they expire.
			buffer := time.Second * 30
			log.Printf("[DEBUG] Initializing OAuth2 token source from external token source with a %.0f second expiration buffer", buffer.Seconds())
			b.tokenSource = oauth2.ReuseTokenSourceWithExpiry(nil, b.ExternalTokenSource, buffer)
		} else {
			log.Printf("[DEBUG] Initializing OAuth2 token source for client ID: %s", b.ClientID)
			b.tokenSource = oauth2.ReuseTokenSource(nil, &boundedClientCredentialsTokenSource{
				config:            config,
				baseTransport:     baseTransport,
				httpClientTimeout: b.HttpClientTimeout,
			})
		}
	}
	tokenSource := b.tokenSource
	b.tsMu.Unlock()

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
		}
	}

	if b.ClientID == "" {
		if clientId, idOk := os.LookupEnv(EnvKeyfactorClientID); idOk {
			b.ClientID = clientId
		} else {
			if serverConfig != nil && serverConfig.ClientID != "" {
				b.ClientID = serverConfig.ClientID
			}
		}
	}

	if b.ClientSecret == "" {
		if clientSecret, sOk := os.LookupEnv(EnvKeyfactorClientSecret); sOk {
			b.ClientSecret = clientSecret
		} else {
			if serverConfig != nil && serverConfig.ClientSecret != "" {
				b.ClientSecret = serverConfig.ClientSecret
			}
		}
	}

	if b.TokenURL == "" {
		if tokenUrl, uOk := os.LookupEnv(EnvKeyfactorAuthTokenURL); uOk {
			b.TokenURL = tokenUrl
		} else {
			if serverConfig != nil && serverConfig.OAuthTokenUrl != "" {
				b.TokenURL = serverConfig.OAuthTokenUrl
			}
		}
	}

	allClientCredentialsProvided := b.ClientID != "" && b.ClientSecret != "" && b.TokenURL != ""

	// Ensure that either all client credentials are provided or an access token/external token source is available.
	if !allClientCredentialsProvided && (b.AccessToken == "" && b.ExternalTokenSource == nil) {
		return ErrMissingClientCredentials
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
	// Delegate to the embedded CommandAuthConfig for the fields it already
	// knows how to populate correctly -- notably ClientTimeout, which must be
	// omitted (not the ValidateAuthConfig-synthesized default) unless the
	// caller explicitly configured it. See clientTimeoutDefaulted's doc
	// comment on CommandAuthConfig for why persisting a synthesized default
	// is harmful. Layer OAuth-specific fields on top.
	server := b.CommandAuthConfig.GetServerConfig()
	server.ClientID = b.ClientID
	server.ClientSecret = b.ClientSecret
	server.AccessToken = b.AccessToken
	server.ExternalTokenSource = b.ExternalTokenSource
	server.OAuthTokenUrl = b.TokenURL
	server.Scopes = b.Scopes
	server.Audience = b.Audience
	server.AuthType = "oauth"
	return server
}

// GetAccessToken returns the OAuth2 token source for the given configuration.
func (b *CommandConfigOauth) GetAccessToken() (*oauth2.Token, error) {
	if b == nil {
		return nil, fmt.Errorf("CommandConfigOauth is nil")
	}

	_ = b.ValidateAuthConfig() // sets client config if not already set but eats the error so that we can return and
	// error fetching the token

	if b.AccessToken != "" && (b.ClientID == "" || b.ClientSecret == "" || b.TokenURL == "") {
		log.Printf("[DEBUG] Access token is explicitly set, and no client credentials are provided. Using static token source.")
		return &oauth2.Token{
			AccessToken: b.AccessToken,
			TokenType:   DefaultTokenPrefix,
			Expiry:      b.Expiry,
		}, nil
	}

	if b.ExternalTokenSource != nil {
		// Unlike GetHttpClient(), this is a single one-shot fetch with no shared cache to
		// consult or populate (the client_credentials branch below is the same: it builds a
		// fresh clientcredentials.Config and fetches every call), so this calls straight
		// through to the caller-supplied source rather than going through the
		// oauth2.ReuseTokenSourceWithExpiry wrapper GetHttpClient() builds into b.tokenSource.
		log.Printf("[DEBUG] Fetching OAuth2 token from external token source")
		token, tErr := b.ExternalTokenSource.Token()
		if tErr != nil {
			return nil, fmt.Errorf("failed to retrieve token from external token source: %w", tErr)
		}
		if token == nil || token.AccessToken == "" {
			return nil, fmt.Errorf("received empty OAuth token from external token source")
		}
		return token, nil
	}

	log.Printf("[DEBUG] Getting OAuth2 token source for client ID: %s", b.ClientID)
	if b.ClientID == "" || b.ClientSecret == "" || b.TokenURL == "" {
		return nil, fmt.Errorf("client ID, client secret, and token URL must be provided")
	}

	config := &clientcredentials.Config{
		ClientID:     b.ClientID,
		ClientSecret: b.ClientSecret,
		TokenURL:     b.TokenURL,
		Scopes:       b.Scopes,
	}

	if b.Audience != "" {
		log.Printf("[DEBUG] Setting audience for OAuth2 token source: %s", b.Audience)
		config.EndpointParams = map[string][]string{
			"audience": {b.Audience},
		}
	}

	// See oauthTokenFetchContext's doc comment: without this, config.Token
	// below falls back to http.DefaultClient, which has no Timeout, so a
	// TCP-connected-but-silent token endpoint would hang this call forever.
	// This is a single one-shot fetch (no caching/reuse across calls like
	// GetHttpClient()'s token source), so the bounded context's lifetime is
	// scoped to just this call via defer cancel().
	baseTransport, tErr := b.BuildTransport()
	if tErr != nil {
		return nil, tErr
	}
	ctx, cancel := oauthTokenFetchContext(baseTransport, b.HttpClientTimeout)
	defer cancel()
	log.Printf("[DEBUG] Fetching OAuth2 token for client ID: %s", b.ClientID)
	token, tErr := config.Token(ctx)
	if tErr != nil {
		return nil, fmt.Errorf("failed to retrieve token for client ID %s: %w", b.ClientID, tErr)
	}
	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("received empty OAuth token for client ID: %s", b.ClientID)
	}

	return token, nil
}

// RoundTrip executes a single HTTP transaction, adding the OAuth2 token to the request
func (t *oauth2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	log.Printf("[DEBUG] Attempting to get oAuth token from: %s %s", req.Method, req.URL)
	token, err := t.src.Token()
	if err != nil {

		return nil, fmt.Errorf("failed to retrieve OAuth token: %w", err)
	}

	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("received empty OAuth token")
	}

	// Clone the request to avoid mutating the original
	log.Printf("[DEBUG] Adding oAuth token to request: %s %s", req.Method, req.URL)
	reqCopy := req.Clone(req.Context())
	token.SetAuthHeader(reqCopy)
	requestCurlStr, _ := RequestToCurl(reqCopy)
	log.Printf("[TRACE] curl command: %s", requestCurlStr)

	return t.base.RoundTrip(reqCopy)
}
