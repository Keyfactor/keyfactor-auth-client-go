# v1.1.1

## Bug fixes
- `oauth2` client now correctly sets the `scopes` and `audience` fields when invoked with explicit values.
- `core` when passing a string for CA certificate check if `.TLSClientConfig.RootCAs` is nil and create a new `CertPool` if it is.

## Chores
- Update `stretchr/testify` to `v1.10.0`  
- Update `AzureAD/microsoft-authentication-library-for-go` to `v1.3.2`  
- Update `x/crypto` to `v0.30.0`  
- Update `x/net` to `v0.32.0`  
- Update `x/sys` to `v0.28.0`  
- Update `x/text` to `v0.21.0`

# v1.1.0

## Features
- Support for sourcing client config files from Azure Key Vault

# v1.0.0

## Features
- Support for `BasicAuth` client config
- Support for `OAuth2` client config
- Support for Keyfactor client config file with `BasicAuth` and `OAuth2` client config(s)