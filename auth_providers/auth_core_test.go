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
	"net/http"
	"strings"
	"testing"

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
