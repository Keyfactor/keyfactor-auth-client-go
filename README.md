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

### Kerberos/SPNEGO Authentication

Kerberos authentication supports three methods: credential cache (ccache), keytab file, or username/password. The authentication method is determined automatically based on which credentials are provided, with the following priority: ccache > keytab > password.

| Name                              | Description                                                                                        | Default           |
|-----------------------------------|----------------------------------------------------------------------------------------------------|-------------------|
| KEYFACTOR_AUTH_KRB_USERNAME       | Kerberos principal (username or user@REALM format)                                                 |                   |
| KEYFACTOR_AUTH_KRB_PASSWORD       | Password for password-based Kerberos authentication                                                |                   |
| KEYFACTOR_AUTH_KRB_REALM          | Kerberos realm (uppercase, e.g., EXAMPLE.COM). Can be implied from username if using user@REALM    |                   |
| KEYFACTOR_AUTH_KRB_KEYTAB         | Path to keytab file for keytab-based authentication                                                |                   |
| KEYFACTOR_AUTH_KRB_CONFIG         | Path to krb5.conf file                                                                             | `/etc/krb5.conf`  |
| KEYFACTOR_AUTH_KRB_CCACHE         | Path to credential cache file for ccache-based authentication                                      |                   |
| KEYFACTOR_AUTH_KRB_SPN            | Service Principal Name (optional, auto-generated as HTTP/hostname if not specified)                |                   |
| KEYFACTOR_AUTH_KRB_DISABLE_PAFXFAST | Set to `true` to disable PA-FX-FAST for Active Directory compatibility                           | `false`           |

### Test Environment Variables

These environment variables are used to run go tests. They are not used in the actual client library.

| Name                    | Description                                           | Default |
|-------------------------|-------------------------------------------------------|---------|
| TEST_KEYFACTOR_AD_AUTH  | Set to `true` to test Active Directory authentication | false   |
| TEST_KEYFACTOR_KC_AUTH  | Set to `true` to test Keycloak authentication         | false   |
| TEST_KEYFACTOR_KRB_AUTH | Set to `true` to test Kerberos authentication         | false   |

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

### Kerberos/SPNEGO

#### JSON (with keytab)

```json
{
  "servers": {
    "default": {
      "host": "keyfactor.command.kfdelivery.com",
      "username": "svc_keyfactor",
      "kerberos_realm": "EXAMPLE.COM",
      "kerberos_keytab": "/etc/keytabs/svc_keyfactor.keytab",
      "kerberos_config": "/etc/krb5.conf",
      "api_path": "KeyfactorAPI"
    }
  }
}
```

#### JSON (with password)

```json
{
  "servers": {
    "default": {
      "host": "keyfactor.command.kfdelivery.com",
      "username": "user@EXAMPLE.COM",
      "password": "password",
      "kerberos_realm": "EXAMPLE.COM",
      "kerberos_config": "/etc/krb5.conf",
      "api_path": "KeyfactorAPI"
    }
  }
}
```

#### YAML (with keytab)

```yaml
servers:
  default:
    host: keyfactor.command.kfdelivery.com
    username: svc_keyfactor
    kerberos_realm: EXAMPLE.COM
    kerberos_keytab: /etc/keytabs/svc_keyfactor.keytab
    kerberos_config: /etc/krb5.conf
    api_path: KeyfactorAPI
```

## Configuration File Providers

Below are a list of configuration file providers that can be used to load configuration from a file if loading from disk
is not desired. 

### Azure Key Vault

To use Azure Key Vault as a configuration file provider, the code must either be running in an Azure environment or the
environment configured with `az login`. The following environment variables can be used and will take precedence over
any configuration file. *NOTE* that the secret must be formatted as specified in the example configuration files above.

| Name                | Description                           | Default |
|---------------------|---------------------------------------|---------|
| AZURE_KEYVAULT_NAME | The name of the Azure KeyVault        |         |
| AZURE_SECRET_NAME   | The name of the Azure KeyVault secret |         |

#### JSON

Below is an example of a configuration file that uses Azure Key Vault as a configuration file provider. *NOTE* that the
secret must be formatted as specified in the example configuration files above.

```json
{
  "servers": {
    "default": {
      "auth_provider": {
        "type": "azid",
        "profile": "default",
        "parameters": {
          "secret_name": "<akv_secret_name>",
          "vault_name": "<akv_vault_name>"
        }
      }
    }
  }
}
```

#### YAML

Below is an example of a configuration file that uses Azure Key Vault as a configuration file provider. *NOTE* that the
secret must be formatted as specified in the example configuration files above.

```yaml
servers:
  default:
    auth_provider:
      type: azid
      profile: default
      parameters:
        secret_name: <akv_secret_name>
        vault_name: <akv_vault_name>
```

# Testing

To run the tests you'll need to provide a `${HOME}/.keyfactor/command_config.json` file for some of the tests to use. 

## Example:

```json
{
  "servers": {
    "default": {
      "host": "<insert keyfactor command hostname>",
      "port": 443,
      "client_id": "<insert valid client_id>",
      "client_secret": "<insert valid client_secret>",
      "token_url": "https://<insert oauth2 token endpoint hostname>/oauth2/token",
      "api_path": "Keyfactor/API",
      "auth_provider": {},
      "skip_tls_verify": true,
      "auth_type": "oauth"
    },
    "basic-auth": {
      "host": "<insert valid keyfactor command hostname>",
      "port": 443,
      "username": "<insert valid keyfactor command username>",
      "password": "<insert valid keyfactor command password>",
      "domain": "<insert valid AD domain name>",
      "api_path": "KeyfactorAPI",
      "auth_provider": {},
      "skip_tls_verify": true,
      "auth_type": "basic"
    },
    "default": {
      "host": "<insert valid keyfactor command hostname>",
      "port": 443,
      "username": "<insert valid keyfactor command username>",
      "password": "<insert valid keyfactor command password>",
      "domain": "<insert valid AD domain name>",
      "api_path": "KeyfactorAPI",
      "auth_provider": {},
      "skip_tls_verify": true,
      "auth_type": "basic"
    },
    "invalid-host": {
      "host": "<insert valid keyfactor command hostname>",
      "port": 443,
      "username": "<insert valid keyfactor command username>",
      "password": "<insert valid keyfactor command password>",
      "domain": "<insert valid AD domain name>",
      "api_path": "KeyfactorAPI",
      "auth_provider": {},
      "skip_tls_verify": true,
      "auth_type": "basic"
    },
    "invalid-username": {
      "host": "<insert valid keyfactor command hostname>",
      "port": 443,
      "username": "invalid",
      "password": "<insert valid keyfactor command password>",
      "domain": "<insert valid AD domain name>",
      "api_path": "KeyfactorAPI",
      "auth_provider": {},
      "skip_tls_verify": true,
      "auth_type": "basic"
    },
    "invalid-password": {
      "host": "<insert valid keyfactor command hostname>",
      "port": 443,
      "username": "<insert valid keyfactor command username>",
      "password": "invalid",
      "domain": "<insert valid AD domain name>",
      "api_path": "KeyfactorAPI",
      "auth_provider": {},
      "skip_tls_verify": true,
      "auth_type": "basic"
    },
    "oauth": {
      "host": "<insert keyfactor command hostname>",
      "port": 443,
      "client_id": "<insert valid client_id>",
      "client_secret": "<insert valid client_secret>",
      "token_url": "https://<insert oauth2 token endpoint hostname>/oauth2/token",
      "api_path": "Keyfactor/API",
      "auth_provider": {},
      "skip_tls_verify": true,
      "auth_type": "oauth"
    },
    "oauth-invalid-creds": {
      "host": "<insert keyfactor command hostname>",
      "port": 443,
      "client_id": "invalid",
      "client_secret": "invalid",
      "token_url": "https://<insert oauth2 token endpoint hostname>/oauth2/token",
      "api_path": "Keyfactor/API",
      "auth_provider": {},
      "skip_tls_verify": true,
      "auth_type": "oauth"
    },
    "oauth-invalid-host": {
      "host": "invalid.localhost.dev",
      "port": 443,
      "client_id": "<insert valid client_id>",
      "client_secret": "<insert valid client_secret>",
      "token_url": "https://<insert oauth2 token endpoint hostname>/oauth2/token",
      "api_path": "Keyfactor/API",
      "auth_provider": {},
      "skip_tls_verify": true,
      "auth_type": "oauth"
    },
    "oauth-skiptls": {
      "host": "<insert keyfactor command hostname>",
      "port": 443,
      "client_id": "<insert valid client_id>",
      "client_secret": "<insert valid client_secret>",
      "token_url": "https://<insert oauth2 token endpoint hostname>/oauth2/token",
      "api_path": "Keyfactor/API",
      "auth_provider": {},
      "skip_tls_verify": true,
      "auth_type": "oauth"
    }
  }
}

```