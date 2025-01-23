# v1.2.0

## Features
- Add logging of the authentication test request as a `curl` string. ([7be00ce](https://github.com/Keyfactor/keyfactor-auth-client-go/commit/7be00ce82b6dd7880449e6585590ec702992a388))

## Bug fixes
- Ensure `CommandAPIPath` is always trimmed of any leading or trailing `/`. ([45023c9](https://github.com/Keyfactor/keyfactor-auth-client-go/commit/45023c94e9be0ae9b307f38af972bbc0b40998d4))
- `oauth` set `DefaultScopes` to empty slice of string rather than `openid`. ([b35d18a](https://github.com/Keyfactor/keyfactor-auth-client-go/commit/b35d18a19430692e65e98623fbfd7300f449bec8))

## Chores
- Bump Go version to `1.23`. ([9e62e2a](https://github.com/Keyfactor/keyfactor-auth-client-go/commit/9e62e2ab3a5c8ea0883df5a5902eaa91f2776f23))

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