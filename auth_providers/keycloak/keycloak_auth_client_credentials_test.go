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
	"os"
	"testing"
)

const (
	TestEnvIsClientAuth = "TEST_KEYFACTOR_KC_AUTH"
)

func TestCommandAuthKeyCloakClientCredentials_AuthEnvironment(t *testing.T) {

	if !checkAuthEnvClientCreds() {
		msg := "Skipping test because Keyfactor Command environment is not authenticated with client credentials"
		t.Log(msg)
		t.Skip(msg)
		return
	}

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

func checkAuthEnvClientCreds() bool {
	if _, ok := os.LookupEnv(TestEnvIsClientAuth); ok {
		return true
	}
	return false
}
