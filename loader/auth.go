// Copyright 2026 Keyfactor
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

package loader

import (
	"fmt"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
)

// ResolvedAuth computes the effective authentication credentials for
// the given tool namespace by overlaying sub-block fields on top of
// the server-level credentials, then validating the resulting tuple
// under strict-mode rules.
//
// Pass an empty namespace ("") to get the server-level view, used by
// callers that target Keyfactor Command directly (kfutil,
// terraform-provider-keyfactor). Tools with their own auth section
// pass their namespace (e.g. "acme").
//
// Strict-mode rules:
//   - Any auth-method-specific field set in the sub-block (e.g.
//     `client_id` under `acme:`) means the sub-block is asserting that
//     method. The entire required tuple must be present in the
//     sub-block; missing fields are NOT silently inherited.
//   - Conversely, an empty sub-block (or one that sets only non-auth
//     fields like base_url) inherits the server-level credentials in
//     full.
//
// This catches "I forgot client_secret" with a clean error instead of
// silently picking up the wrong secret from the parent level.
func (l *Loader) ResolvedAuth(namespace string) (*auth_providers.AuthCreds, error) {
	if !l.loaded {
		return nil, fmt.Errorf("loader.ResolvedAuth called before Load")
	}

	// Server-level view comes from Load's cached, overlaid Server so
	// env-var and flag overrides aren't lost.
	serverCreds := auth_providers.AuthCredsFromServer(l.cachedServer)

	if namespace == "" {
		if _, err := serverCreds.Validate(); err != nil {
			return nil, fmt.Errorf("server-level auth: %w", err)
		}
		return serverCreds, nil
	}

	// Sub-block view.
	var subCreds auth_providers.AuthCreds
	subKey := "servers." + l.resolvedProfile + "." + namespace
	if l.v.IsSet(subKey) {
		if err := l.v.UnmarshalKey(subKey, &subCreds, decoderOpts()); err != nil {
			return nil, fmt.Errorf("unmarshal %q sub-block auth fields: %w", namespace, err)
		}
	}

	merged, err := overlayAuth(serverCreds, &subCreds)
	if err != nil {
		return nil, fmt.Errorf("%s auth: %w", namespace, err)
	}
	if _, err := merged.Validate(); err != nil {
		return nil, fmt.Errorf("%s auth: %w", namespace, err)
	}
	return merged, nil
}

// overlayAuth applies sub-block fields on top of server-level fields
// per the strict-mode rules documented on ResolvedAuth. Returns the
// merged AuthCreds or an error when the sub-block declares a partial
// method override.
func overlayAuth(server, sub *auth_providers.AuthCreds) (*auth_providers.AuthCreds, error) {
	if subDeclaresMethod(sub) {
		// Sub-block is asserting its own method — return a fresh tuple
		// taking ONLY from the sub-block. Inheritance is disabled to
		// avoid the half-and-half case where (say) client_id is from
		// the sub-block but client_secret leaks in from the parent.
		out := *sub
		return &out, nil
	}
	// No method assertion in the sub-block; inherit everything.
	out := *server
	return &out, nil
}

// subDeclaresMethod reports whether the sub-block sets ANY field
// indicative of an auth method assertion. Fields that don't belong to
// a specific method (audience, scopes, domain alone) don't trigger it.
func subDeclaresMethod(sub *auth_providers.AuthCreds) bool {
	if sub == nil {
		return false
	}
	if sub.AuthType != "" {
		return true
	}
	switch {
	case sub.Username != "" || sub.Password != "":
		return true
	case sub.ClientID != "" || sub.ClientSecret != "" || sub.TokenURL != "":
		return true
	case sub.AccessToken != "":
		return true
	case sub.KerberosKeytab != "" || sub.KerberosCCache != "" || sub.KerberosRealm != "":
		return true
	}
	return false
}
