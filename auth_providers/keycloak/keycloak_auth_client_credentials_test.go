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

package keycloak

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCommandAuthKeyCloakClientCredentials_AuthenticateMocked(t *testing.T) {
	// Create a test server that returns a 200 status and a token
	ts := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"access_token": "test_token", "expires_in": 3600}`))
			},
		),
	)
	defer ts.Close()

	// Create a new CommandAuthKeyCloakClientCredentials instance
	//c := &CommandAuthKeyCloakClientCredentials{
	//	ClientID:     "test_client_id",
	//	ClientSecret: "test_client_secret",
	//	Realm:        "test_realm",
	//	TokenURL:     ts.URL, // Use the URL of the test server
	//}

	//// Call the Authenticate method
	//err := c.Authenticate()
	//if err != nil {
	//	t.Errorf("Authenticate() error = %v", err)
	//	return
	//}
	//
	//// Check that the AuthHeader was set correctly
	//expectedAuthHeader := "Bearer test_token"
	//if c.AuthHeader != expectedAuthHeader {
	//	t.Errorf("Authenticate() AuthHeader = %v, want %v", c.AuthHeader, expectedAuthHeader)
	//}
}

func TestCommandAuthKeyCloakClientCredentials_AuthEnvironment(t *testing.T) {

	// Create a new CommandAuthKeyCloakClientCredentials instance
	c := &CommandAuthKeyCloakClientCredentials{} //Used environment configuration

	// Call the Authenticate method
	err := c.Authenticate()
	if err != nil {
		t.Errorf("Authenticate() error = %v", err)
		return
	}

	// Check that the AuthHeader was set correctly
	expectedAuthHeader := fmt.Sprintf("Bearer %s", c.AccessToken)
	if c.AuthHeader != expectedAuthHeader {
		t.Errorf("Authenticate() AuthHeader = %v, want %v", c.AuthHeader, expectedAuthHeader)
	}
}
