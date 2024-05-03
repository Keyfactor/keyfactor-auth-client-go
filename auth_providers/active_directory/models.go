package active_directory

import (
	"keyfactor_auth/auth_providers"
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
