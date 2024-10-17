package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	// Generate CA private key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Failed to generate CA private key: %v\n", err)
		return
	}

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"My CA Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create CA certificate
	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Printf("Failed to create CA certificate: %v\n", err)
		return
	}

	// Encode CA certificate to PEM format
	caCertPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCertBytes,
		},
	)

	// Encode CA private key to PEM format
	caPrivKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
		},
	)

	// Save CA certificate and private key to files
	err = os.WriteFile("ca_cert.pem", caCertPEM, 0644)
	if err != nil {
		fmt.Printf("Failed to write CA certificate to file: %v\n", err)
		return
	}
	err = os.WriteFile("ca_key.pem", caPrivKeyPEM, 0600)
	if err != nil {
		fmt.Printf("Failed to write CA private key to file: %v\n", err)
		return
	}

	// Generate leaf private key
	leafPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Failed to generate leaf private key: %v\n", err)
		return
	}

	// Create leaf certificate template
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"My Leaf Organization"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0), // 1 year
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	// Create leaf certificate signed by the CA
	leafCertBytes, err := x509.CreateCertificate(
		rand.Reader,
		leafTemplate,
		caTemplate,
		&leafPrivKey.PublicKey,
		caPrivKey,
	)
	if err != nil {
		fmt.Printf("Failed to create leaf certificate: %v\n", err)
		return
	}

	// Encode leaf certificate to PEM format
	leafCertPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: leafCertBytes,
		},
	)

	// Encode leaf private key to PEM format
	leafPrivKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(leafPrivKey),
		},
	)

	// Save leaf certificate and private key to files
	err = os.WriteFile("leaf_cert.pem", leafCertPEM, 0644)
	if err != nil {
		fmt.Printf("Failed to write leaf certificate to file: %v\n", err)
		return
	}
	err = os.WriteFile("leaf_key.pem", leafPrivKeyPEM, 0600)
	if err != nil {
		fmt.Printf("Failed to write leaf private key to file: %v\n", err)
		return
	}

	fmt.Println("CA and leaf certificates generated successfully.")
}
