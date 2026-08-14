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

package auth_providers_test

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
)

func TestCommandAuthConfig_ValidateAuthConfig(t *testing.T) {
	config := &auth_providers.CommandAuthConfig{
		CommandHostName: "test-host",
		CommandPort:     443,
		CommandAPIPath:  "KeyfactorAPI",
	}

	err := config.ValidateAuthConfig()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCommandAuthConfig_BuildTransport(t *testing.T) {
	config := &auth_providers.CommandAuthConfig{
		CommandHostName: "test-host",
		CommandPort:     443,
		CommandAPIPath:  "KeyfactorAPI",
	}

	transport, err := config.BuildTransport()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if transport == nil {
		t.Fatalf("expected a non-nil http.Transport")
	}
}

func TestCommandAuthConfig_SetClient(t *testing.T) {
	config := &auth_providers.CommandAuthConfig{}

	client := &http.Client{}
	config.SetClient(client)

	if config.HttpClient != client {
		t.Fatalf("expected HttpClient to be set")
	}
}

// TestCommandAuthConfig_ClientTimeout_ServerRoundTrip is a regression test for
// https://github.com/Keyfactor/keyfactor-auth-client-go/issues/51: a
// WithClientTimeout value set on CommandAuthConfig must survive the round trip
// through GetServerConfig()'s *Server representation instead of being silently
// dropped. Before the fix, Server had no ClientTimeout field at all, so this
// assertion failed to compile/would read the Go zero value (0).
func TestCommandAuthConfig_ClientTimeout_ServerRoundTrip(t *testing.T) {
	config := &auth_providers.CommandAuthConfig{
		CommandHostName: "test-host",
		CommandPort:     443,
		CommandAPIPath:  "KeyfactorAPI",
	}
	config.WithClientTimeout(300)

	server := config.GetServerConfig()
	if server.ClientTimeout != 300 {
		t.Fatalf("expected Server.ClientTimeout to be 300, got %d", server.ClientTimeout)
	}
}

// TestCommandAuthConfig_ClientTimeout_BuildTransport is a regression test proving
// that a non-default client timeout actually reaches BuildTransport()'s derived
// ResponseHeaderTimeout (the field responsible for the customer-observed
// "net/http: timeout awaiting response headers" error at the default 60s).
func TestCommandAuthConfig_ClientTimeout_BuildTransport(t *testing.T) {
	config := &auth_providers.CommandAuthConfig{
		CommandHostName: "test-host",
		CommandPort:     443,
		CommandAPIPath:  "KeyfactorAPI",
	}
	config.WithClientTimeout(300)

	transport, err := config.BuildTransport()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expected := 300 * time.Second
	if transport.ResponseHeaderTimeout != expected {
		t.Fatalf("expected ResponseHeaderTimeout to be %v, got %v", expected, transport.ResponseHeaderTimeout)
	}
}

// writeTimeoutConfigFile writes a minimal config file with a single "default"
// profile carrying the given client_timeout (in seconds) and returns its path.
func writeTimeoutConfigFile(t *testing.T, clientTimeout int) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/command_config.json"
	contents := fmt.Sprintf(
		`{"servers":{"default":{"host":"file-host.example.com","client_timeout":%d}}}`,
		clientTimeout,
	)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("failed to write test config file: %v", err)
	}
	return path
}

// TestCommandAuthConfig_ClientTimeout_FileConfigHonored is a regression test
// proving that a client_timeout set only in a config file profile is actually
// honored end-to-end: LoadConfig -> ValidateAuthConfig -> BuildTransport.
// Before the fix, LoadConfig never merged Server.ClientTimeout into
// CommandAuthConfig.HttpClientTimeout (unlike Host/Port/APIPath/CACertPath/
// SkipVerify, which it already merged), and ValidateAuthConfig never
// consulted c.FileConfig as a fallback (unlike the CommandHostName branch),
// so the file value was silently dropped and HttpClientTimeout landed on the
// 60s default instead.
func TestCommandAuthConfig_ClientTimeout_FileConfigHonored(t *testing.T) {
	path := writeTimeoutConfigFile(t, 300)

	config := &auth_providers.CommandAuthConfig{}
	config.WithConfigFile(path).WithConfigProfile("default")

	if _, err := config.LoadConfig(config.ConfigProfile, config.ConfigFilePath, true); err != nil {
		t.Fatalf("expected no error from LoadConfig, got %v", err)
	}

	if config.FileConfig == nil || config.FileConfig.ClientTimeout != 300 {
		t.Fatalf("expected FileConfig.ClientTimeout to be 300, got %+v", config.FileConfig)
	}

	if err := config.ValidateAuthConfig(); err != nil {
		t.Fatalf("expected no error from ValidateAuthConfig, got %v", err)
	}

	if config.HttpClientTimeout != 300 {
		t.Fatalf("expected HttpClientTimeout to be 300, got %d", config.HttpClientTimeout)
	}

	transport, err := config.BuildTransport()
	if err != nil {
		t.Fatalf("expected no error from BuildTransport, got %v", err)
	}

	expected := 300 * time.Second
	if transport.ResponseHeaderTimeout != expected {
		t.Fatalf("expected ResponseHeaderTimeout to be %v, got %v", expected, transport.ResponseHeaderTimeout)
	}
}

// TestCommandAuthConfig_ClientTimeout_FileConfigFallbackOnly is a narrower
// regression test isolating the ValidateAuthConfig fallback path: it sets
// FileConfig directly (as would happen if a caller populates it without
// LoadConfig's eager merge) and confirms ValidateAuthConfig still falls back
// to it, mirroring the existing CommandHostName/c.FileConfig fallback
// convention in this function.
func TestCommandAuthConfig_ClientTimeout_FileConfigFallbackOnly(t *testing.T) {
	config := &auth_providers.CommandAuthConfig{
		CommandHostName: "test-host",
		CommandPort:     443,
		CommandAPIPath:  "KeyfactorAPI",
		FileConfig:      &auth_providers.Server{ClientTimeout: 120},
	}

	if err := config.ValidateAuthConfig(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if config.HttpClientTimeout != 120 {
		t.Fatalf("expected HttpClientTimeout to be 120, got %d", config.HttpClientTimeout)
	}
}

// TestCommandAuthConfig_ClientTimeout_Precedence proves the full fallback
// chain resolves in the intended order: explicit struct value/WithClientTimeout()
// wins outright; absent that, LoadConfig's eager file merge (mirroring how
// Host/Port/APIPath/CACertPath/SkipVerify are merged) takes effect before
// ValidateAuthConfig's env var check ever runs, so a config file value takes
// precedence over the environment variable -- consistent with how
// CommandHostName already behaves in this codebase (LoadConfig always runs
// before ValidateAuthConfig in every concrete auth type's ValidateAuthConfig
// wrapper, so a file-resolved field is never re-overridden by env). Finally,
// with neither struct, file, nor env set, the package default applies.
func TestCommandAuthConfig_ClientTimeout_Precedence(t *testing.T) {
	t.Run("struct value wins over file and env", func(t *testing.T) {
		t.Setenv(auth_providers.EnvKeyfactorClientTimeout, "45")
		path := writeTimeoutConfigFile(t, 300)

		config := &auth_providers.CommandAuthConfig{}
		config.WithConfigFile(path).WithConfigProfile("default")
		config.WithClientTimeout(15)

		if _, err := config.LoadConfig(config.ConfigProfile, config.ConfigFilePath, true); err != nil {
			t.Fatalf("expected no error from LoadConfig, got %v", err)
		}
		if err := config.ValidateAuthConfig(); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if config.HttpClientTimeout != 15 {
			t.Fatalf("expected HttpClientTimeout to be 15, got %d", config.HttpClientTimeout)
		}
	})

	t.Run("file value wins over env when no struct value is set", func(t *testing.T) {
		t.Setenv(auth_providers.EnvKeyfactorClientTimeout, "45")
		path := writeTimeoutConfigFile(t, 300)

		config := &auth_providers.CommandAuthConfig{}
		config.WithConfigFile(path).WithConfigProfile("default")

		if _, err := config.LoadConfig(config.ConfigProfile, config.ConfigFilePath, true); err != nil {
			t.Fatalf("expected no error from LoadConfig, got %v", err)
		}
		if err := config.ValidateAuthConfig(); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if config.HttpClientTimeout != 300 {
			t.Fatalf("expected HttpClientTimeout to be 300 (file value), got %d", config.HttpClientTimeout)
		}
	})

	t.Run("env value used when no struct or file value is set", func(t *testing.T) {
		t.Setenv(auth_providers.EnvKeyfactorClientTimeout, "45")

		config := &auth_providers.CommandAuthConfig{
			CommandHostName: "test-host",
			CommandPort:     443,
			CommandAPIPath:  "KeyfactorAPI",
		}

		if err := config.ValidateAuthConfig(); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if config.HttpClientTimeout != 45 {
			t.Fatalf("expected HttpClientTimeout to be 45 (env value), got %d", config.HttpClientTimeout)
		}
	})

	t.Run("default used when nothing else is set", func(t *testing.T) {
		config := &auth_providers.CommandAuthConfig{
			CommandHostName: "test-host",
			CommandPort:     443,
			CommandAPIPath:  "KeyfactorAPI",
		}

		if err := config.ValidateAuthConfig(); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if config.HttpClientTimeout != auth_providers.DefaultClientTimeout {
			t.Fatalf(
				"expected HttpClientTimeout to be default %d, got %d",
				auth_providers.DefaultClientTimeout, config.HttpClientTimeout,
			)
		}
	})
}

// TestCommandAuthConfig_ClientTimeout_BadEnvVarNeverDisablesTimeout is a
// regression test for the unbounded-wait hazard: os.LookupEnv reports ok=true
// for a set-but-empty env var, and an unparseable/non-positive value must
// never leave HttpClientTimeout at its zero value, since a zero timeout
// means "no timeout" throughout net/http (ResponseHeaderTimeout,
// TLSHandshakeTimeout, IdleConnTimeout, http.Client.Timeout), and
// Authenticate() builds requests with no context to otherwise bound them.
func TestCommandAuthConfig_ClientTimeout_BadEnvVarNeverDisablesTimeout(t *testing.T) {
	badValues := []string{"", "abc", "60s", "0", "-5"}

	for _, v := range badValues {
		v := v
		t.Run(fmt.Sprintf("env=%q", v), func(t *testing.T) {
			t.Setenv(auth_providers.EnvKeyfactorClientTimeout, v)

			config := &auth_providers.CommandAuthConfig{
				CommandHostName: "test-host",
				CommandPort:     443,
				CommandAPIPath:  "KeyfactorAPI",
			}

			if err := config.ValidateAuthConfig(); err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if config.HttpClientTimeout != auth_providers.DefaultClientTimeout {
				t.Fatalf(
					"expected HttpClientTimeout to fall back to default %d for env value %q, got %d",
					auth_providers.DefaultClientTimeout, v, config.HttpClientTimeout,
				)
			}

			transport, err := config.BuildTransport()
			if err != nil {
				t.Fatalf("expected no error from BuildTransport, got %v", err)
			}

			expected := time.Duration(auth_providers.DefaultClientTimeout) * time.Second
			if transport.ResponseHeaderTimeout != expected || transport.ResponseHeaderTimeout == 0 {
				t.Fatalf(
					"expected ResponseHeaderTimeout to be %v for env value %q, got %v (0 means unlimited)",
					expected, v, transport.ResponseHeaderTimeout,
				)
			}
		})
	}
}

func TestCommandAuthConfig_Authenticate(t *testing.T) {
	config := &auth_providers.CommandAuthConfig{
		CommandHostName: "test-host",
		CommandPort:     443,
		CommandAPIPath:  "KeyfactorAPI",
	}

	err := config.Authenticate()
	if err == nil {
		t.Fatalf("expected an error, got nil")
	}
}

func TestLoadCACertificates(t *testing.T) {
	_, err := auth_providers.LoadCACertificates("../lib/test_ca_cert.pem")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestFindCACertificate(t *testing.T) {
	_, err := auth_providers.FindCACertificate("../lib/test_chain.pem")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestDecodePEMBytes(t *testing.T) {
	pemData := []byte(`-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7Q2+1+2+1+2+1+2+1+2+
-----END CERTIFICATE-----`)
	blocks, _, err := auth_providers.DecodePEMBytes(pemData)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(blocks) == 0 {
		t.Fatalf("expected non-zero blocks")
	}
}

func TestRequestToCurl(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		url           string
		headers       map[string]string
		wantInCurl    []string
		notWantInCurl []string
	}{
		{
			name:   "Basic Auth",
			method: "GET",
			url:    "https://example.com/api",
			headers: map[string]string{
				"Authorization": "Basic dXNlcjpwYXNz",
			},
			wantInCurl: []string{
				"curl", "-X", "GET", "https://example.com/api",
				"-H", "Authorization: Basic",
			},
			notWantInCurl: []string{
				"Authorization: Basic dXNlcjpwYXNz",
			},
		},
		{
			name:   "Bearer Auth",
			method: "POST",
			url:    "https://example.com/token",
			headers: map[string]string{
				"Authorization": "Bearer testtoken",
				"Content-Type":  "application/json",
			},
			wantInCurl: []string{
				"curl", "-X", "POST", "https://example.com/token",
				"-H", "Authorization: Bearer",
				"-H", "Content-Type: application/json",
			},
			notWantInCurl: []string{
				"Authorization: Bearer testtoken",
			},
		},
	}

	for _, tt := range tests {
		req, err := http.NewRequest(tt.method, tt.url, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		for k, v := range tt.headers {
			req.Header.Set(k, v)
		}

		curlStr, err := auth_providers.RequestToCurl(req)
		if err != nil {
			t.Errorf("%s: RequestToCurl returned error: %v", tt.name, err)
			continue
		}
		for _, want := range tt.wantInCurl {
			if !strings.Contains(curlStr, want) {
				t.Errorf("%s: curl string missing %q\nGot: %s", tt.name, want, curlStr)
			}
		}

		for _, notWant := range tt.notWantInCurl {
			if strings.Contains(curlStr, notWant) {
				t.Errorf("%s: curl string contains unwanted %q\nGot: %s", tt.name, notWant, curlStr)
			}
		}
		t.Logf("%s: curl command: %s", tt.name, curlStr)
	}
}
