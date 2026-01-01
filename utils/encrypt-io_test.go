package utils

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestStreamEncryptIo(t *testing.T) {
	pass := "1qa2ws"
	EncryptFile("dircopy-linux.go", "dircopy-linux.go.enc", pass, "")
	DecryptFile("dircopy-linux.go.enc", "dircopy-linux.go.dec", pass, "")
}

// ---------- Example / quick test ----------
func TestAESCTR(t *testing.T) {
	plain := []byte("The quick brown fox jumps over the lazy dog. This is a longer message to test chunking.")
	// use buffer as destination
	var outBuf bytes.Buffer

	// create writer
	w, err := NewStreamEncryptWriter(&outBuf, "correct horse battery staple")
	if err != nil {
		fmt.Println("writer init:", err)
		return
	}

	// write plaintext (bigger than chunk to test flushes)
	if _, err := w.Write(plain); err != nil {
		fmt.Println("write err:", err)
		return
	}
	// MUST close to flush final chunk
	if err := w.Close(); err != nil {
		fmt.Println("writer close:", err)
		return
	}

	// decrypt
	r, err := NewStreamDecryptReader(io.NopCloser(bytes.NewReader(outBuf.Bytes())), "correct horse battery staple")
	if err != nil {
		fmt.Println("reader init:", err)
		return
	}
	decrypted, err := io.ReadAll(r)
	if err != nil {
		fmt.Println("read all:", err)
		return
	}
	_ = r.Close()

	if !bytes.Equal(decrypted, plain) {
		fmt.Println("mismatch!")
		fmt.Printf("got:  %q\n", decrypted)
		fmt.Printf("want: %q\n", plain)
		os.Exit(2)
	}
	fmt.Println("OK — roundtrip succeeded, plaintext:", string(decrypted))
}

func TestCompEnc(t *testing.T) {
	compEncOpt := NewCompEncOptions().WithPassword("1qa2ws").WithOverwriteExisting(true)
	CheckErr(CreateCompEncArchive("go.sum", "go.sum.zst.enc", compEncOpt), "")
	CheckErr(ExtractCompEncArchive("go.sum.zst.enc", "go.sum.dec", compEncOpt), "")
	// Test fifo
	fifo := "/tmp/test-fifo"
	os.RemoveAll(fifo)
	CheckErr(unix.Mkfifo(fifo, uint32(0600)), "")
	defer os.RemoveAll(fifo)
	go func() {
		CreateCompEncArchive(fifo, "go.sum.zst.enc", compEncOpt)
	}()
	time.Sleep(200 * time.Millisecond)
	o := Must(RunSystemCommandV2(`cat go.sum > `+fifo, true))
	println(o)
	CheckErr(ExtractCompEncArchive("go.sum.zst.enc", "go.sum.dec", compEncOpt), "")

}
