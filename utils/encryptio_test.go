package utils

import (
	"io"
	"os"
	"testing"
)

func DecryptFile(inFile, outFile string, password string) error {
	f := Must(os.Open(inFile))
	defer f.Close()

	r := Must(NewAESCTRReader(f, password))
	defer r.Close() // this closes the file

	inf := Must(os.Create(outFile))
	defer inf.Close()
	_, err := io.Copy(inf, r)
	return err
}

func TestEncWriter(t *testing.T) {
	outFile, _ := os.Create("encrypted.data")
	encWriter := NewAESCTRWriter(outFile, "strong-password")

	infile := Must(os.Open("/home/sitsxk5/kernel/linux-6.13.2.tar.xz"))
	io.Copy(encWriter, infile)

}

func TestEncReader(t *testing.T) {
	CheckErr(DecryptFile("encrypted.data", "linux.tar.xz", "strong-password"), "")
}
