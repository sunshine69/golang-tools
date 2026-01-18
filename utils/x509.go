package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
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

// CheckCertExpiry takes a domain address (e.g., "example.com:443") and a threshold
// in days. It returns true if the certificate expires within that threshold.
func CheckCertExpiry(address string, daysThreshold int) (bool, error) {
	// Establish a TLS connection
	conn, err := tls.Dial("tcp", address, nil)
	if err != nil {
		return false, fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	defer conn.Close()

	// Get the leaf certificate (index 0 should be the main cert)
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return false, fmt.Errorf("no certificates found for %s", address)
	}
	cert := certs[0]
	expiry := cert.NotAfter

	// Calculate time remaining and compare with the threshold
	durationUntilExpiry := time.Until(expiry)
	daysLeft := durationUntilExpiry.Hours() / 24

	// Convert the integer threshold to a Duration for clear comparison
	thresholdDuration := time.Duration(daysThreshold) * 24 * time.Hour
	isExpiringSoon := durationUntilExpiry < thresholdDuration

	fmt.Printf("Domain: %s\nExpiry Date: %v\nDays Remaining: %.1f\n",
		address, expiry.Format(time.RFC822), daysLeft)

	return isExpiringSoon, nil
}

// PrivateKeyConstraint matches the core Go private key types
// and ensures they satisfy the crypto.Signer interface.
type PrivateKeyConstraint interface {
	*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
	Public() crypto.PublicKey
}

// Generate bunch of key type. Call it with empty key and select type you want to generate, it will fill the value and turn back
func GenerateX509Keypair[T PrivateKeyConstraint](initialKey T, data map[string]any) (T, any, *x509.CertificateRequest) {
	// Define your custom fields
	commonName := MapLookup(data, "COMMON_NAME", "example.com").(string)
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{MapLookup(data, "CSR_COUNTRY", "AU").(string)},
			Organization:       []string{MapLookup(data, "CSR_ORG", "Home").(string)},
			OrganizationalUnit: []string{MapLookup(data, "CSR_ORG_UNIT", "IT Department").(string)},
			Locality:           []string{MapLookup(data, "CSR_LOCALITY", "Brisbane").(string)},
			CommonName:         commonName,
		},
		DNSNames: strings.Split(commonName, ","),
	}
	var privateKey, publicKeyOut any
	var err error
	switch _keyType := any(initialKey).(type) {
	case *rsa.PrivateKey:
		// Generate a private key for the CSR
		privateKey = Must(rsa.GenerateKey(rand.Reader, 2048))
		publicKeyOut = &(privateKey.(*rsa.PrivateKey)).PublicKey
	case *ecdsa.PrivateKey:
		privateKey = Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
		publicKeyOut = &(privateKey.(*ecdsa.PrivateKey)).PublicKey
	case *ed25519.PrivateKey:
		publicKeyOut, privateKey, err = ed25519.GenerateKey(rand.Reader)
		CheckErr(err, "ed25519.GenerateKey")
	default:
		fmt.Fprintf(os.Stderr, "[ERROR] Not support this type %v\n", _keyType)
		os.Exit(1)
	}

	// Create the CSR in DER format
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	fmt.Fprintln(os.Stderr, JsonDump(csrDER, ""))
	// 4. Parse the bytes back into the *x509.CertificateRequest struct
	csr := Must(x509.ParseCertificateRequest(csrDER))

	keyT := privateKey.(T)
	os.WriteFile(MapLookup(data, "KEY_OUT", "server.key").(string), Must(MarshalPKCS8PrivatePEM(keyT)), 0o600)
	// publicKeyOut - Except ed25519 one which is []byte not a pointer, all other must be a pointer
	os.WriteFile(MapLookup(data, "PUBLIC_KEY_OUT", "server.crt").(string), Must(MarshalPKIXPublicKeyPEM(publicKeyOut)), 0o600)
	os.WriteFile(MapLookup(data, "CSR_OUT", "server.csr").(string), MarshalCSRPEM(csr), 0o600)
	return privateKey.(T), publicKeyOut, csr
}

func MarshalCSRPEM(csr *x509.CertificateRequest) []byte {
	// Wrap the raw DER bytes (csr.Raw) in a PEM block
	csrBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}

	// Encode to memory (returns []byte)
	return pem.EncodeToMemory(csrBlock)
}
func MarshalPKIXPublicKeyPEM(pubKey any) ([]byte, error) {
	// 1. Convert to DER-encoded PKIX (SubjectPublicKeyInfo) format
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	// 2. Wrap in a PEM block
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}

	// 3. Encode to memory
	return pem.EncodeToMemory(pubBlock), nil
}

func MarshalPKCS8PrivatePEM[T PrivateKeyConstraint](privKey T) ([]byte, error) {
	// 1. Convert to DER-encoded PKCS#8 format
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, err
	}

	// 2. Wrap in a PEM block
	privBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	}

	return pem.EncodeToMemory(privBlock), nil
}
