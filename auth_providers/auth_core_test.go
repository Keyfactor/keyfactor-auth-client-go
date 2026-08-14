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
	"encoding/json"
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

// TestCommandAuthConfig_IdleAndExpectContinueTimeouts_NotDerivedFromClientTimeout
// is a regression test for a resource leak: BuildTransport() and SetClient()
// both derived IdleConnTimeout and ExpectContinueTimeout from the same
// HttpClientTimeout value used for the request deadline
// (ResponseHeaderTimeout). IdleConnTimeout governs how long an *idle* pooled
// connection is retained -- it is not a request deadline -- so a large
// configured HttpClientTimeout (e.g. 1800s, exactly what's needed for slow
// PFX enrollments) caused idle sockets and their goroutines to be retained
// for the full 1800s after every request, instead of net/http's normal 90s.
// A large `terraform apply` issuing many sequential requests therefore held
// open hundreds of sockets/goroutines for half an hour. ExpectContinueTimeout
// has the same bug for the same reason.
//
// ResponseHeaderTimeout must continue to track HttpClientTimeout -- that is
// the customer-facing fix the timeout work exists for -- while
// IdleConnTimeout and ExpectContinueTimeout must stay pinned to fixed,
// sane defaults (matching net/http.DefaultTransport) regardless of how large
// HttpClientTimeout is configured.
func TestCommandAuthConfig_IdleAndExpectContinueTimeouts_NotDerivedFromClientTimeout(t *testing.T) {
	config := &auth_providers.CommandAuthConfig{
		CommandHostName: "test-host",
		CommandPort:     443,
		CommandAPIPath:  "KeyfactorAPI",
	}
	config.WithClientTimeout(1800)

	t.Run("BuildTransport", func(t *testing.T) {
		transport, err := config.BuildTransport()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if expected := 1800 * time.Second; transport.ResponseHeaderTimeout != expected {
			t.Fatalf("expected ResponseHeaderTimeout to be %v, got %v", expected, transport.ResponseHeaderTimeout)
		}
		if transport.IdleConnTimeout != auth_providers.DefaultIdleConnTimeout {
			t.Fatalf(
				"expected IdleConnTimeout to stay pinned at the fixed default %v regardless of a 1800s HttpClientTimeout, got %v",
				auth_providers.DefaultIdleConnTimeout, transport.IdleConnTimeout,
			)
		}
		if transport.ExpectContinueTimeout != auth_providers.DefaultExpectContinueTimeout {
			t.Fatalf(
				"expected ExpectContinueTimeout to stay pinned at the fixed default %v regardless of a 1800s HttpClientTimeout, got %v",
				auth_providers.DefaultExpectContinueTimeout, transport.ExpectContinueTimeout,
			)
		}
	})

	t.Run("SetClient", func(t *testing.T) {
		client := config.SetClient(nil)
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("expected client.Transport to be *http.Transport, got %T", client.Transport)
		}

		if expected := 1800 * time.Second; transport.ResponseHeaderTimeout != expected {
			t.Fatalf("expected ResponseHeaderTimeout to be %v, got %v", expected, transport.ResponseHeaderTimeout)
		}
		if transport.IdleConnTimeout != auth_providers.DefaultIdleConnTimeout {
			t.Fatalf(
				"expected IdleConnTimeout to stay pinned at the fixed default %v regardless of a 1800s HttpClientTimeout, got %v",
				auth_providers.DefaultIdleConnTimeout, transport.IdleConnTimeout,
			)
		}
		if transport.ExpectContinueTimeout != auth_providers.DefaultExpectContinueTimeout {
			t.Fatalf(
				"expected ExpectContinueTimeout to stay pinned at the fixed default %v regardless of a 1800s HttpClientTimeout, got %v",
				auth_providers.DefaultExpectContinueTimeout, transport.ExpectContinueTimeout,
			)
		}
	})
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

// TestCommandAuthConfig_GetServerConfig_DoesNotPersistSynthesizedDefault is a
// regression test for a precedence bug introduced alongside the
// HttpClientTimeout/Server.ClientTimeout round trip: GetServerConfig()
// serialized the *resolved* HttpClientTimeout, including the 60s value
// ValidateAuthConfig synthesizes when nothing was configured. A caller that
// persists GetServerConfig()'s output to a config file (as kfutil's login
// flow does) would therefore always write client_timeout: 60 to disk, even
// though the user never chose it -- see
// TestCommandAuthConfig_PersistedDefaultConfigFile_DoesNotShadowEnvVar for
// why that phantom value is actively harmful on the next run.
//
// A value that was never explicitly configured (no struct field, no
// WithClientTimeout(), no env var, no file value) must not be serialized.
func TestCommandAuthConfig_GetServerConfig_DoesNotPersistSynthesizedDefault(t *testing.T) {
	config := &auth_providers.CommandAuthConfig{
		CommandHostName: "test-host",
		CommandPort:     443,
		CommandAPIPath:  "KeyfactorAPI",
	}

	if err := config.ValidateAuthConfig(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if config.HttpClientTimeout != auth_providers.DefaultClientTimeout {
		t.Fatalf("expected HttpClientTimeout to be defaulted to %d, got %d", auth_providers.DefaultClientTimeout, config.HttpClientTimeout)
	}

	server := config.GetServerConfig()
	if server.ClientTimeout != 0 {
		t.Fatalf("expected Server.ClientTimeout to be omitted (0) for a synthesized default, got %d", server.ClientTimeout)
	}
}

// TestCommandAuthConfig_GetServerConfig_PersistsExplicitTimeout proves the
// companion positive case: an explicitly configured timeout (whether set
// directly, via WithClientTimeout(), via the environment, or via a file
// value already present on CommandAuthConfig.FileConfig before
// ValidateAuthConfig runs) must still be serialized by GetServerConfig(), so
// TestCommandAuthConfig_ClientTimeout_ServerRoundTrip's guarantee is
// preserved.
func TestCommandAuthConfig_GetServerConfig_PersistsExplicitTimeout(t *testing.T) {
	t.Run("WithClientTimeout", func(t *testing.T) {
		config := &auth_providers.CommandAuthConfig{
			CommandHostName: "test-host",
			CommandPort:     443,
			CommandAPIPath:  "KeyfactorAPI",
		}
		config.WithClientTimeout(300)

		if err := config.ValidateAuthConfig(); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		server := config.GetServerConfig()
		if server.ClientTimeout != 300 {
			t.Fatalf("expected Server.ClientTimeout to be 300, got %d", server.ClientTimeout)
		}
	})

	t.Run("environment variable", func(t *testing.T) {
		t.Setenv(auth_providers.EnvKeyfactorClientTimeout, "1800")

		config := &auth_providers.CommandAuthConfig{
			CommandHostName: "test-host",
			CommandPort:     443,
			CommandAPIPath:  "KeyfactorAPI",
		}

		if err := config.ValidateAuthConfig(); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		server := config.GetServerConfig()
		if server.ClientTimeout != 1800 {
			t.Fatalf("expected Server.ClientTimeout to be 1800, got %d", server.ClientTimeout)
		}
	})

	t.Run("file config fallback", func(t *testing.T) {
		config := &auth_providers.CommandAuthConfig{
			CommandHostName: "test-host",
			CommandPort:     443,
			CommandAPIPath:  "KeyfactorAPI",
			FileConfig:      &auth_providers.Server{ClientTimeout: 120},
		}

		if err := config.ValidateAuthConfig(); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		server := config.GetServerConfig()
		if server.ClientTimeout != 120 {
			t.Fatalf("expected Server.ClientTimeout to be 120, got %d", server.ClientTimeout)
		}
	})
}

// TestCommandAuthConfig_PersistedDefaultConfigFile_DoesNotShadowEnvVar is an
// end-to-end regression test for the actual customer-facing bug: kfutil's
// login flow calls ValidateAuthConfig() then GetServerConfig(), and persists
// the result verbatim to ~/.keyfactor/command_config.json. Before the fix,
// that meant a run with nothing configured wrote client_timeout: 60 to disk.
// On the *next* run, LoadConfig merges that file value into
// CommandAuthConfig.HttpClientTimeout before ValidateAuthConfig ever runs
// (mirroring how Host/Port/etc. are merged), so ValidateAuthConfig's
// `if c.HttpClientTimeout <= 0` guard was already false and the
// KEYFACTOR_CLIENT_TIMEOUT env var branch was skipped entirely --
// permanently and silently shadowing the env var, with no diagnostic. This
// is a real regression: the env var always worked before Server gained a
// ClientTimeout field to persist.
//
// This test reproduces the full two-run cycle: run 1 resolves nothing
// explicit and persists its Server config to a file; run 2 loads that file
// with KEYFACTOR_CLIENT_TIMEOUT set and must honor the env var.
func TestCommandAuthConfig_PersistedDefaultConfigFile_DoesNotShadowEnvVar(t *testing.T) {
	// Run 1: nothing explicitly configured.
	run1 := &auth_providers.CommandAuthConfig{
		CommandHostName: "test-host",
		CommandPort:     443,
		CommandAPIPath:  "KeyfactorAPI",
	}
	if err := run1.ValidateAuthConfig(); err != nil {
		t.Fatalf("run1: expected no error, got %v", err)
	}

	persisted := run1.GetServerConfig()

	// Persist exactly what kfutil's login flow persists: the resolved Server
	// config, verbatim, to the "default" profile of a config file.
	dir := t.TempDir()
	path := dir + "/command_config.json"
	fileContents, mErr := json.Marshal(map[string]interface{}{
		"servers": map[string]interface{}{
			"default": persisted,
		},
	})
	if mErr != nil {
		t.Fatalf("failed to marshal persisted config: %v", mErr)
	}
	if err := os.WriteFile(path, fileContents, 0o600); err != nil {
		t.Fatalf("failed to write persisted config file: %v", err)
	}

	// Run 2: a fresh process loads that persisted file and has
	// KEYFACTOR_CLIENT_TIMEOUT set in its environment.
	t.Setenv(auth_providers.EnvKeyfactorClientTimeout, "1800")

	run2 := &auth_providers.CommandAuthConfig{}
	run2.WithConfigFile(path).WithConfigProfile("default")

	if _, err := run2.LoadConfig(run2.ConfigProfile, run2.ConfigFilePath, true); err != nil {
		t.Fatalf("run2: expected no error from LoadConfig, got %v", err)
	}

	if err := run2.ValidateAuthConfig(); err != nil {
		t.Fatalf("run2: expected no error from ValidateAuthConfig, got %v", err)
	}

	if run2.HttpClientTimeout != 1800 {
		t.Fatalf(
			"expected KEYFACTOR_CLIENT_TIMEOUT=1800 to be honored, but a persisted synthesized default shadowed it: got HttpClientTimeout=%d",
			run2.HttpClientTimeout,
		)
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

// TestRequestToCurl_BodyRedaction is a regression test for secrets being
// logged verbatim in the curl command RequestToCurl produces. Before the
// fix, RequestToCurl appended the raw request body via `--data %q` with no
// redaction at all, so any secret-bearing payload (e.g. a PFX enrollment
// request carrying a private-key password) was written in plaintext to the
// log whenever TRACE logging is enabled -- which is exactly what support
// asks a customer to enable when reporting the slow-request/timeout issues
// this library exists to fix, so plaintext secrets would routinely end up in
// support bundles.
//
// The fix must redact known-sensitive field values from JSON and
// form-encoded bodies while preserving the rest of the body for
// diagnostics, and must never fall back to printing a body it can't safely
// classify.
func TestRequestToCurl_BodyRedaction(t *testing.T) {
	tests := []struct {
		name          string
		contentType   string
		body          string
		wantInCurl    []string
		notWantInCurl []string
	}{
		{
			name:        "JSON top-level sensitive key",
			contentType: "application/json",
			body:        `{"Password":"SuperSecret1","CommonName":"test.example.com"}`,
			wantInCurl: []string{
				`\"CommonName\":\"test.example.com\"`,
				`\"Password\":\"***REDACTED***\"`,
			},
			notWantInCurl: []string{
				"SuperSecret1",
			},
		},
		{
			name:        "JSON nested sensitive key",
			contentType: "application/json",
			body:        `{"Subject":"CN=test","PFXPassword":{"Value":"NestedSecret!","SecretSource":"Inline"}}`,
			wantInCurl: []string{
				`\"Subject\":\"CN=test\"`,
				`\"PFXPassword\":\"***REDACTED***\"`,
			},
			notWantInCurl: []string{
				"NestedSecret!",
				"SecretSource",
			},
		},
		{
			name:        "JSON sensitive key inside array element",
			contentType: "application/json",
			body:        `{"Stores":[{"StoreId":"abc","KeyPassword":"ArraySecret"}]}`,
			wantInCurl: []string{
				`\"StoreId\":\"abc\"`,
				`\"KeyPassword\":\"***REDACTED***\"`,
			},
			notWantInCurl: []string{
				"ArraySecret",
			},
		},
		{
			name:        "JSON case-insensitive key match",
			contentType: "application/json",
			body:        `{"clientSecret":"CaseSecret","Name":"svc"}`,
			wantInCurl: []string{
				`\"Name\":\"svc\"`,
				`\"clientSecret\":\"***REDACTED***\"`,
			},
			notWantInCurl: []string{
				"CaseSecret",
			},
		},
		{
			name:        "Form-encoded body with client_secret",
			contentType: "application/x-www-form-urlencoded",
			body:        "grant_type=client_credentials&client_id=my-client&client_secret=FormSecret",
			wantInCurl: []string{
				"grant_type=client_credentials",
				"client_id=my-client",
				"client_secret=%2A%2A%2AREDACTED%2A%2A%2A",
			},
			notWantInCurl: []string{
				"FormSecret",
			},
		},
		{
			name:        "Opaque/unknown content type is omitted entirely",
			contentType: "application/octet-stream",
			body:        "raw-binary-looking-payload-with-a-Password=OpaqueSecret-inside",
			wantInCurl: []string{
				"redacted",
				"application/octet-stream",
			},
			notWantInCurl: []string{
				"OpaqueSecret",
				"raw-binary-looking-payload",
			},
		},
		{
			name:        "Empty body",
			contentType: "application/json",
			body:        "",
			wantInCurl: []string{
				"curl", "-X", "POST",
			},
		},
		{
			name:        "JSON body with no sensitive keys stays fully visible",
			contentType: "application/json",
			body:        `{"CommonName":"test.example.com","Template":"WebServer"}`,
			wantInCurl: []string{
				`\"CommonName\":\"test.example.com\"`,
				`\"Template\":\"WebServer\"`,
			},
		},
	}

	for _, tt := range tests {
		req, err := http.NewRequest("POST", "https://example.com/api", strings.NewReader(tt.body))
		if err != nil {
			t.Fatalf("%s: failed to create request: %v", tt.name, err)
		}
		if tt.contentType != "" {
			req.Header.Set("Content-Type", tt.contentType)
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

// TestCommandAuthConfig_MaxConnsPerHost_Unbounded is a regression test for a
// global-concurrency-cap bug: newHTTPTransport() hardcoded
// MaxConnsPerHost: 10. That was harmless as long as every request built its
// own throwaway transport, but consumers (e.g. keyfactor-go-client) now
// correctly cache and reuse a single *http.Client/*http.Transport across all
// requests to fix a socket leak -- which turns MaxConnsPerHost: 10 into a
// hard ceiling of 10 concurrent in-flight requests per host, no matter how
// much client-side parallelism (e.g. `terraform apply -parallelism=25`)
// callers configure. Since the returned client has Timeout: 0 and requests
// carry no context deadline, requests beyond the 10th queue with no bound.
//
// MaxConnsPerHost must match net/http.DefaultTransport's unbounded default
// (0), while the idle-connection pool limits (which bound long-term resource
// retention, not concurrency) stay as configured.
func TestCommandAuthConfig_MaxConnsPerHost_Unbounded(t *testing.T) {
	config := &auth_providers.CommandAuthConfig{
		CommandHostName: "test-host",
		CommandPort:     443,
		CommandAPIPath:  "KeyfactorAPI",
	}

	t.Run("BuildTransport", func(t *testing.T) {
		transport, err := config.BuildTransport()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if transport.MaxConnsPerHost != 0 {
			t.Fatalf("expected MaxConnsPerHost to be unbounded (0), got %d", transport.MaxConnsPerHost)
		}
		if transport.MaxIdleConns != 10 {
			t.Fatalf("expected MaxIdleConns to stay at 10, got %d", transport.MaxIdleConns)
		}
		if transport.MaxIdleConnsPerHost != 10 {
			t.Fatalf("expected MaxIdleConnsPerHost to stay at 10, got %d", transport.MaxIdleConnsPerHost)
		}
	})

	t.Run("SetClient", func(t *testing.T) {
		client := config.SetClient(nil)
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("expected client.Transport to be *http.Transport, got %T", client.Transport)
		}
		if transport.MaxConnsPerHost != 0 {
			t.Fatalf("expected MaxConnsPerHost to be unbounded (0), got %d", transport.MaxConnsPerHost)
		}
		if transport.MaxIdleConns != 10 {
			t.Fatalf("expected MaxIdleConns to stay at 10, got %d", transport.MaxIdleConns)
		}
		if transport.MaxIdleConnsPerHost != 10 {
			t.Fatalf("expected MaxIdleConnsPerHost to stay at 10, got %d", transport.MaxIdleConnsPerHost)
		}
	})
}
