package utils

import (
	"testing"
	"log"
)

func TestUtils(t *testing.T) {
	// o := RunSystemCommand("ls /", true)
	// fmt.Printf("OUT: %v\n", o)
	a := GenRandomString(12)
	log.Println(a)
}

func TestUnzip(t *testing.T) {
	err := Unzip("Downloads/artifacts.zip", ".")
	CheckErr(err, "  ")
}

func TestBcryptHash(t *testing.T) {
	hashed, _ := BcryptHashPassword("1q2w3e", -1)
	log.Printf("Hash: %s\n", hashed)
	Assert (BcryptCheckPasswordHash("1q2w3e", hashed), "OK", false)
}