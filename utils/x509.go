package utils

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func LoadPrivateKeyFromPEM(filePath string) (crypto.PrivateKey, error) {
	// 1. Read the key file
	keyBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// 2. Decode the PEM block
	block, rest := pem.Decode(keyBytes)
	if block == nil {
		if len(rest) > 0 {
			return nil, fmt.Errorf("failed to decode PEM block, data remains")
		}
		return nil, fmt.Errorf("failed to decode PEM block from file %s: no PEM data found", filePath)
	}

	// 3. Parse the key based on its type
	var privateKey any

	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 RSA private key: %w", err)
		}
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
	default:
		// Attempt to parse as PKCS#8 (a common, standard format)
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse as PKCS#8 private key: %w", err)
		}

	}

	// 4. Cast the parsed key to the crypto.PrivateKey interface
	if pk, ok := privateKey.(crypto.PrivateKey); ok {
		return pk, nil
	}

	return nil, fmt.Errorf("unsupported private key type after parsing")
}
