variable "keyfactor_hostname_10_5_0" {
  description = "The hostname of the Keyfactor instance"
  type        = string
  default     = "integrations1050-lab.kfdelivery.com"
}

variable "keyfactor_username_10_5_0" {
  description = "The username to authenticate with the Keyfactor instance"
  type        = string
}

variable "keyfactor_password_10_5_0" {
  description = "The password to authenticate with the Keyfactor instance"
  type        = string
}

variable "keyfactor_client_id_12_3_0" {
  description = "The client ID to authenticate with the Keyfactor instance using Keycloak client credentials"
  type        = string
}

variable "keyfactor_client_secret_12_3_0" {
  description = "The client secret to authenticate with the Keyfactor instance using Keycloak client credentials"
  type        = string
}

variable "keyfactor_hostname_12_3_0_KC" {
  description = "The hostname of the Keyfactor instance"
  type        = string
  default     = "int1230-oauth.eastus2.cloudapp.azure.com"

}

variable "keyfactor_auth_token_url_12_3_0_KC" {
  description = "The hostname of the KeyCloak instance to authenticate to for a Keyfactor Command access token"
  type        = string
  default     = "https://int1230-oauth.eastus2.cloudapp.azure.com:8444/realms/Keyfactor/protocol/openid-connect/token"
}

variable "keyfactor_client_id_ses_2441" {
  description = "The client ID to authenticate with the Keyfactor instance using Keycloak client credentials"
  type        = string
}

variable "keyfactor_client_secret_ses_2441" {
  description = "The client secret to authenticate with the Keyfactor instance using Keycloak client credentials"
  type        = string
}

variable "keyfactor_hostname_ses_2441" {
  description = "The hostname of the Keyfactor instance"
  type        = string
  default     = "int2441.kftestlab.com"

}

variable "keyfactor_auth_token_url_ses_2441" {
  description = "The hostname of the KeyCloak instance to authenticate to for a Keyfactor Command access token"
  type        = string
  default     = "https://auth.kftestlab.com/oauth2/token"
}