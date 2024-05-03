package main

import (
	"log"

	"keyfactor_auth/auth_providers/keycloak"
)

func main() {
	//try client auth
	keyfactorAuthConfig := keycloak.CommandAuthKeyCloakClientCredentials{}
	aErr := keyfactorAuthConfig.Authenticate()
	if aErr != nil {
		log.Fatalf("[ERROR] %s\n", aErr)
	}
	log.Println("[INFO] Successfully authenticated with Keyfactor")
	log.Println("[INFO] Token: ", keyfactorAuthConfig.AccessToken)
	log.Println("[INFO] Refresh Token: ", keyfactorAuthConfig.RefreshToken)
	log.Println("[INFO] Token Expiry: ", keyfactorAuthConfig.Expiry)

}
