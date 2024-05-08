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

package auth_providers

// CommandAuthConfigBasic represents the base configuration needed for authentication to Keyfactor Command API.
type CommandAuthConfigBasic struct {
	// CommandAuthConfig is a reference to the base configuration needed for authentication to Keyfactor Command API
	CommandAuthConfig

	// Username is the username to be used for authentication to Keyfactor Command API
	Username string `json:"username"`

	// Password is the password to be used for authentication to Keyfactor Command API
	Password string `json:"password"`
}
