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
