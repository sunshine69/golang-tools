package utils

import (
	"testing"
)

func TestDirCopy(t *testing.T) {
	err := CopyDirectory("/home/sitsxk5/src/gorecurcopy/tests", "tests")
	if err != nil {
		println(err.Error())
	}
}
