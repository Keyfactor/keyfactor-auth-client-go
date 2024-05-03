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
	HttpClient      *http.Client
}

const (
	DefaultCommandPort    = "443"
	DefaultCommandAPIPath = "KeyfactorAPI"
	EnvKeyfactorHostName  = "KEYFACTOR_HOSTNAME"
	EnvKeyfactorPort      = "KEYFACTOR_PORT"
	EnvKeyfactorAPIPath   = "KEYFACTOR_API_PATH"
)

type CommandAuthConfigBasic struct {
	CommandAuthConfig
	Username string `json:"username"`
	Password string `json:"password"`
}
