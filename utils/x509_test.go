package utils

import (
	"crypto/rsa"
	"testing"
)

func TestCheckCertExpiry(t *testing.T) {
	if Must(CheckCertExpiry("google.com:443", 15)) {
		println("Expire")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	GenerateX509Keypair(&rsa.PrivateKey{}, map[string]any{})
}
