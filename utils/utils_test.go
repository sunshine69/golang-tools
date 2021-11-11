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