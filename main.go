// Copyright 2024 Keyfactor
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

package main

import (
	"fmt"

	"github.com/Keyfactor/keyfactor-auth-client-go/pkg"
)

func main() {
	fmt.Println("Version:", pkg.Version)   // print the package version
	fmt.Println("Build:", pkg.BuildTime)   // print the package build
	fmt.Println("Commit:", pkg.CommitHash) // print the package commit
	//testClients()
}

//func testClients() {
//	// URL to test against
//	url := os.Getenv("KEYFACTOR_AUTH_TOKEN_URL")
//	caCertPath := os.Getenv("KEYFACTOR_CA_CERT")
//
//	// Load the custom root CA certificate
//	caCert, err := os.ReadFile(caCertPath)
//	if err != nil {
//		log.Fatalf("Failed to read root CA certificate: %v", err)
//	}
//
//	// Create a certificate pool and add the custom root CA
//	caCertPool := x509.NewCertPool()
//	if !caCertPool.AppendCertsFromPEM(caCert) {
//		log.Fatalf("Failed to append root CA certificate to pool")
//	}
//
//	// OAuth2 client credentials configuration
//	clientId := os.Getenv("KEYFACTOR_AUTH_CLIENT_ID")
//	clientSecret := os.Getenv("KEYFACTOR_AUTH_CLIENT_SECRET")
//	oauthConfig := &clientcredentials.Config{
//		ClientID:     clientId,
//		ClientSecret: clientSecret,
//		TokenURL:     url,
//	}
//
//	// Transport with default TLS verification (InsecureSkipVerify = false)
//	transportDefaultTLS := &http.Transport{
//		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
//	}
//
//	// Transport with TLS verification skipped (InsecureSkipVerify = true)
//	transportInsecureTLS := &http.Transport{
//		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
//	}
//
//	// Transport with custom CA verification
//	transportCustomRootCA := &http.Transport{
//		TLSClientConfig: &tls.Config{
//			RootCAs:            caCertPool, // Custom root CA pool
//			InsecureSkipVerify: false,      // Enforce TLS verification
//		},
//	}
//
//	// OAuth2 Token Sources
//	tokenSourceDefaultTLS := oauthConfig.TokenSource(context.Background())
//
//	ctxInsecure := context.WithValue(
//		context.Background(),
//		oauth2.HTTPClient,
//		&http.Client{Transport: transportInsecureTLS},
//	)
//	tokenSourceInsecureTLS := oauthConfig.TokenSource(ctxInsecure)
//
//	ctxCustomCA := context.WithValue(
//		context.Background(),
//		oauth2.HTTPClient,
//		&http.Client{Transport: transportCustomRootCA},
//	)
//	tokenSourceCustomRootCA := oauthConfig.TokenSource(ctxCustomCA)
//
//	// OAuth2 clients with different transports
//	oauthClientDefaultTLS := &http.Client{
//		Transport: &oauth2Transport{
//			base: transportDefaultTLS,
//			src:  tokenSourceDefaultTLS,
//		},
//	}
//
//	oauthClientInsecureTLS := &http.Client{
//		Transport: &oauth2Transport{
//			base: transportInsecureTLS,
//			src:  tokenSourceInsecureTLS,
//		},
//	}
//
//	oauthClientCustomRootCA := &http.Client{
//		Transport: &oauth2Transport{
//			base: transportCustomRootCA,
//			src:  tokenSourceCustomRootCA,
//		},
//	}
//
//	// Prepare the GET request
//	req, err := http.NewRequest("GET", url, nil)
//	if err != nil {
//		log.Fatalf("Failed to create request: %v", err)
//	}
//
//	// Test 1: OAuth2 client with default TLS verification (expected to fail if certificate is invalid)
//	fmt.Println("Testing OAuth2 client with default TLS verification...")
//	resp1, err1 := oauthClientDefaultTLS.Do(req)
//	if err1 != nil {
//		log.Printf("OAuth2 client with default TLS failed as expected: %v\n", err1)
//	} else {
//		fmt.Printf("OAuth2 client with default TLS succeeded: %s\n", resp1.Status)
//		resp1.Body.Close()
//	}
//
//	// Test 2: OAuth2 client with skipped TLS verification (should succeed)
//	fmt.Println("\nTesting OAuth2 client with skipped TLS verification...")
//	resp2, err2 := oauthClientInsecureTLS.Do(req)
//	if err2 != nil {
//		log.Fatalf("OAuth2 client with skipped TLS failed: %v\n", err2)
//	} else {
//		fmt.Printf("OAuth2 client with skipped TLS succeeded: %s\n", resp2.Status)
//		resp2.Body.Close()
//	}
//
//	// Test 3: OAuth2 client with custom root CA (should succeed if the CA is valid)
//	fmt.Println("\nTesting OAuth2 client with custom root CA verification...")
//	resp3, err3 := oauthClientCustomRootCA.Do(req)
//	if err3 != nil {
//		log.Fatalf("OAuth2 client with custom root CA failed: %v\n", err3)
//	} else {
//		fmt.Printf("OAuth2 client with custom root CA succeeded: %s\n", resp3.Status)
//		resp3.Body.Close()
//	}
//}
//
//// oauth2Transport is a custom RoundTripper that injects the OAuth2 token into requests
//type oauth2Transport struct {
//	base http.RoundTripper
//	src  oauth2.TokenSource
//}
//
//// RoundTrip executes a single HTTP transaction, adding the OAuth2 token to the request
//func (t *oauth2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
//	token, err := t.src.Token()
//	if err != nil {
//		return nil, fmt.Errorf("failed to retrieve OAuth token: %w", err)
//	}
//
//	// Clone the request to avoid mutating the original
//	reqCopy := req.Clone(req.Context())
//	token.SetAuthHeader(reqCopy)
//
//	return t.base.RoundTrip(reqCopy)
//}
