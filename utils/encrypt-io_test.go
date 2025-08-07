package utils

import (
	"io"
	"os"
	"testing"
)

func TestStreamEncryptIo(t *testing.T) {
	pr, pw, _ := os.Pipe()
	ew := NewAESCTRWriter(pw, `1qa2ws`)
	go ew.Write([]byte(`This is to be encrytped`))

	er, _ := NewAESCTRReader(pr, `1qa2ws`)
	defer er.Close()
	o := Must(io.ReadAll(er))
	println(string(o))
}
