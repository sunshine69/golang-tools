package utils

import (
	"testing"
)

func TestEncWriter(t *testing.T) {
	EncryptFile("in", "out", "asd")
}

func TestEncReader(t *testing.T) {
	CheckErr(DecryptFile("encrypted.data", "linux.tar.xz", "strong-password"), "")
}
