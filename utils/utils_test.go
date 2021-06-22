package utils

import (
	"testing"
)

func TestUtils(t *testing.T) {
	// o := RunSystemCommand("ls /", true)
	// fmt.Printf("OUT: %v\n", o)
	GenSelfSignedKey("test-key-hen")
}
