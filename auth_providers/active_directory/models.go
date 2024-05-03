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
	"keyfactor_auth_client/auth_providers"
)

const (
	EnvKeyfactorDomain   = "KEYFACTOR_DOMAIN"
	EnvKeyfactorUsername = "KEYFACTOR_USERNAME"
	EnvKeyfactorPassword = "KEYFACTOR_PASSWORD"
)

type CommandAuthConfigActiveDirectory struct {
	auth_providers.CommandAuthConfigBasic
	Domain string `json:"domain"`
}
