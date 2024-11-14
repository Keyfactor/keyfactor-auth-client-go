# keyfactor-auth-client-go

Client library for authenticating to Keyfactor Command.

## Environment Variables

### Global

| Name                          | Description                                                                                                     | Default                                |
|-------------------------------|-----------------------------------------------------------------------------------------------------------------|----------------------------------------|
| KEYFACTOR_HOSTNAME            | Keyfactor Command hostname without protocol and port                                                            |                                        |
| KEYFACTOR_PORT                | Keyfactor Command port                                                                                          | `443`                                  |
| KEYFACTOR_API_PATH            | Keyfactor Command API Path                                                                                      | `KeyfactorAPI`                         |
| KEYFACTOR_SKIP_VERIFY         | Skip TLS verification when connecting to Keyfactor Command                                                      | `false`                                |
| KEYFACTOR_CA_CERT             | Either a file path or PEM encoded string to a CA certificate to trust when communicating with Keyfactor Command |                                        |
| KEYFACTOR_CLIENT_TIMEOUT      | Timeout for HTTP client requests to Keyfactor Command                                                           | `60s`                                  |
| KEYFACTOR_AUTH_CONFIG_FILE    | Path to a JSON file containing the authentication configuration                                                 | `$HOME/.keyfactor/command_config.json` |
| KEYFACTOR_AUTH_CONFIG_PROFILE | Profile to use from the authentication configuration file                                                       | `default`                              |

### Basic Auth

Currently `Basic Authentication` via `Active Directory` is the *ONLY* supported method of `Basic Authentication`.

| Name               | Description                                                                                 | Default |
|--------------------|---------------------------------------------------------------------------------------------|---------|
| KEYFACTOR_USERNAME | Active Directory username to authenticate to Keyfactor Command API                          |         |
| KEYFACTOR_PASSWORD | Password associated with Active Directory username to authenticate to Keyfactor Command API |         |
| KEYFACTOR_DOMAIN   | Active Directory domain of user. Can be implied from username if it contains `@` or `\\`    |         |

### oAuth Client Credentials

| Name                         | Description                                                                                                                     | Default  |
|------------------------------|---------------------------------------------------------------------------------------------------------------------------------|----------|
| KEYFACTOR_AUTH_CLIENT_ID     | Keyfactor Auth Client ID                                                                                                        |          |
| KEYFACTOR_AUTH_CLIENT_SECRET | Keyfactor Auth Client Secret                                                                                                    |          |
| KEYFACTOR_AUTH_TOKEN_URL     | URL to request an access token from Keyfactor Auth                                                                              |          |
| KEYFACTOR_AUTH_SCOPES        | Scopes to request when authenticating to Keyfactor Command API. Each scope MUST be separated by `,`                             | `openid` |
| KEYFACTOR_AUTH_AUDIENCE      | Audience to request when authenticating to Keyfactor Command API                                                                |          |
| KEYFACTOR_AUTH_ACCESS_TOKEN  | Access token to use to authenticate to Keyfactor Command API. This can be supplied directly or generated via client credentials |          |
| KEYFACTOR_AUTH_CA_CERT       | Either a file path or PEM encoded string to a CA certificate to use when connecting to Keyfactor Auth                           |          |

### Test Environment Variables

These environment variables are used to run go tests. They are not used in the actual client library.

| Name                   | Description                                           | Default |
|------------------------|-------------------------------------------------------|---------|
| TEST_KEYFACTOR_AD_AUTH | Set to `true` to test Active Directory authentication | false   |
| TEST_KEYFACTOR_KC_AUTH | Set to `true` to test Keycloak authentication         | false   |

## Configuration File

A JSON or YAML file can be used to store authentication configuration. A configuration file can contain references to
multiple Keyfactor Command environments and can be referenced by a `profile` name. The `default` profile will be used
when no profile is specified. Keyfactor tools will look for a config file located at
`$HOME/.keyfactor/command_config.json`
by default. The config file should be structured as follows:

### Basic Auth

#### JSON

```json
{
  "servers": {
    "default": {
      "host": "keyfactor.command.kfdelivery.com",
      "username": "keyfactor",
      "password": "password",
      "domain": "command",
      "api_path": "KeyfactorAPI"
    },
    "server2": {
      "host": "keyfactor2.command.kfdelivery.com",
      "username": "keyfactor2",
      "password": "password2",
      "domain": "command",
      "api_path": "Keyfactor/API"
    }
  }
}
```

#### YAML

```yaml
servers:
  default:
    host: keyfactor.command.kfdelivery.com
    username: keyfactor
    password: password
    domain: command
    api_path: KeyfactorAPI
  server2:
    host: keyfactor2.command.kfdelivery.com
    username: keyfactor2
    password: password2
    domain: command
    api_path: Keyfactor/API
```

### oAuth Client Credentials

#### JSON

```json
{
  "servers": {
    "default": {
      "host": "keyfactor.command.kfdelivery.com",
      "token_url": "https://idp.keyfactor.command.kfdelivery.com/oauth2/token",
      "client_id": "client-id",
      "client_secret": "client-secret",
      "audience": "https://keyfactor.command.kfdelivery.com",
      "scopes": [
        "openid",
        "profile",
        "email"
      ],
      "api_path": "KeyfactorAPI"
    },
    "server2": {
      "host": "keyfactor.command.kfdelivery.com",
      "token_url": "https://idp.keyfactor.command.kfdelivery.com/oauth2/token",
      "client_id": "client-id",
      "client_secret": "client-secret",
      "api_path": "KeyfactorAPI"
    }
  }
}
```

#### YAML

```yaml
servers:
  default:
    host: keyfactor.command.kfdelivery.com
    token_url: https://idp.keyfactor.command.kfdelivery.com/oauth2/token
    client_id: client-id
    client_secret: client-secret
    api_path: KeyfactorAPI
    audience: https://keyfactor.command.kfdelivery.com
    scopes:
      - openid
      - profile
      - email
  server2:
    host: keyfactor.command.kfdelivery.com
    token_url: https://idp.keyfactor.command.kfdelivery.com/oauth2/token
    client_id: client-id
    client_secret: client-secret
    api_path: KeyfactorAPI
```