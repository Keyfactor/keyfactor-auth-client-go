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

import (
	"net/http"
)

type CommandAuthConfig struct {
	ConfigType      string `json:"config_type"`
	AuthHeader      string `json:"auth_header"`
	CommandHostName string `json:"command_host_name"`
	CommandPort     string `json:"command_port"`
	CommandAPIPath  string `json:"command_api_path"`
	CommandVersion  string `json:"command_version"`
	HttpClient      *http.Client
}

const (
	DefaultCommandPort    = "443"
	DefaultCommandAPIPath = "KeyfactorAPI"
	DefaultAPIVersion     = "1"
	DefaultAPIClientName  = "APIClient"
	DefaultProductVersion = "10.5.0.0"
	EnvKeyfactorHostName  = "KEYFACTOR_HOSTNAME"
	EnvKeyfactorPort      = "KEYFACTOR_PORT"
	EnvKeyfactorAPIPath   = "KEYFACTOR_API_PATH"
)

type CommandAuthConfigBasic struct {
	CommandAuthConfig
	Username string `json:"username"`
	Password string `json:"password"`
}
