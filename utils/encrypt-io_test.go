package utils

import (
	"testing"
)

func TestStreamEncryptIo(t *testing.T) {
	pass := "1qa2ws"
	EncryptFile("dircopy-linux.go", "dircopy-linux.go.enc", pass)
	DecryptFile("dircopy-linux.go.enc", "dircopy-linux.go.dec", pass)
}
