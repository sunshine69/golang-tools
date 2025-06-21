package utils

import (
	"testing"
)

func TestDirCopy(t *testing.T) {
	err := CopyDirectory("/home/stevek/src/gorecurcopy/tests", "tests")
	if err != nil {
		println(err.Error())
	}
}
