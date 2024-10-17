# keyfactor-auth-client-go

Client library for authenticating to Keyfactor Command

<!-- toc -->

- [Environment Variables](#environment-variables)
    * [Global](#global)
    * [Active Directory](#active-directory)
    * [Keycloak](#keycloak)
        + [Client Credentials](#client-credentials)
- [Test Environment Variables](#test-environment-variables)

<!-- tocstop -->

## Environment Variables

### Global

| Name                  | Description                                                  | Default        |
|-----------------------|--------------------------------------------------------------|----------------|
| KEYFACTOR_HOSTNAME    | Keyfactor Command hostname without protocol and port         |                |
| KEYFACTOR_PORT        | Keyfactor Command port                                       | `443`          |
| KEYFACTOR_API_PATH    | Keyfactor Command API Path                                   | `KeyfactorAPI` |
| KEYFACTOR_SKIP_VERIFY | Skip TLS verification when connecting to Keyfactor Command   | `false`        |
| KEYFACTOR_CA_CERT     | Either a file path or PEM encoded string to a CA certificate |                |

### Active Directory

| Name               | Description                                                                                 | Default |
|--------------------|---------------------------------------------------------------------------------------------|---------|
| KEYFACTOR_USERNAME | Active Directory username to authenticate to Keyfactor Command API                          |         |
| KEYFACTOR_PASSWORD | Password associated with Active Directory username to authenticate to Keyfactor Command API |         |
| KEYFACTOR_DOMAIN   | Active Directory domain of user. Can be implied from username if it contains `@` or `\\`    |         |

### Keycloak

| Name                    | Description                                                                                                                     | Default     |
|-------------------------|---------------------------------------------------------------------------------------------------------------------------------|-------------|
| KEYFACTOR_AUTH_HOSTNAME | Hostname of Keycloak instance to authenticate to Keyfactor Command                                                              |             |
| KEYFACTOR_AUTH_REALM    | Keyfactor Auth Realm                                                                                                            | `Keyfactor` |
| KEYFACTOR_AUTH_SCOPES   | Scopes to request when authenticating to Keyfactor Command API                                                                  | `openid`    |
| KEYFACTOR_ACCESS_TOKEN  | Access token to use to authenticate to Keyfactor Command API. This can be supplied directly or generated via client credentials |             |
| KEYFACTOR_AUTH_CA_CERT  | Either a file path or PEM encoded string to a CA certificate to use when connecting to Keyfactor Auth                           |             |

#### Client Credentials

| Name                         | Description                  | Default |
|------------------------------|------------------------------|---------|
| KEYFACTOR_AUTH_CLIENT_ID     | Keyfactor Auth Client ID     |         |
| KEYFACTOR_AUTH_CLIENT_SECRET | Keyfactor Auth Client Secret |         |

## Test Environment Variables

These environment variables are used to run go tests. They are not used in the actual client library.

| Name                   | Description                                           | Default |
|------------------------|-------------------------------------------------------|---------|
| TEST_KEYFACTOR_AD_AUTH | Set to `true` to test Active Directory authentication | false   |
| TEST_KEYFACTOR_KC_AUTH | Set to `true` to test Keycloak authentication         | false   |