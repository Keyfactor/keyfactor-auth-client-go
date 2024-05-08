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

package active_directory

import (
	"fmt"
	"os"
	"testing"
)

const (
	TestEnvIsADAuth = "TEST_KEYFACTOR_AD_AUTH"
)

func TestCommandAuthActiveDirectoryCredentials_AuthEnvironment(t *testing.T) {

	if !checkAuthEnvADCreds() {
		msg := "Skipping test because Keyfactor Command environment is not authenticated with Active Directory credentials"
		t.Log(msg)
		t.Skip(msg)
		return
	}
	// Create a new CommandAuthActiveDirectoryCredentials instance
	c := &CommandAuthConfigActiveDirectory{} //Used environment configuration

	// Call the Authenticate method
	err := c.Authenticate()
	if err != nil {
		t.Errorf("Authenticate() error = %v", err)
		return
	}

	// Check that the AuthHeader was set correctly
	expectedAuthHeader := fmt.Sprintf("Basic %s", c.getBasicAuthHeader())
	if c.AuthHeader != expectedAuthHeader {
		t.Errorf("Authenticate() AuthHeader = %v, want %v", c.AuthHeader, expectedAuthHeader)
	}
}

func checkAuthEnvADCreds() bool {
	if _, ok := os.LookupEnv(TestEnvIsADAuth); ok {
		return true
	}
	return false
}
