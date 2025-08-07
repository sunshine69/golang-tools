package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

// Option 1: Return io.WriteCloser instead of io.Writer
type encryptedFileWriter struct {
	writer   io.Writer
	password string
	buffer   []byte
	closed   bool
}

// CreateEncryptionWriter returns io.WriteCloser so callers can close it
func CreateEncryptionWriter(w io.Writer, password string) io.WriteCloser {
	return &encryptedFileWriter{
		writer:   w,
		password: password,
		buffer:   make([]byte, 0),
		closed:   false,
	}
}

func (ew *encryptedFileWriter) Write(data []byte) (int, error) {
	if ew.closed {
		return 0, fmt.Errorf("writer is closed")
	}
	ew.buffer = append(ew.buffer, data...)
	return len(data), nil
}

func (ew *encryptedFileWriter) Close() error {
	if ew.closed {
		return nil
	}
	ew.closed = true

	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Write salt to output
	if _, err := ew.writer.Write(salt); err != nil {
		return fmt.Errorf("failed to write salt: %w", err)
	}

	// Derive key from password using PBKDF2
	key := pbkdf2.Key([]byte(ew.password), salt, 100000, 32, sha256.New)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Write nonce to output
	if _, err := ew.writer.Write(nonce); err != nil {
		return fmt.Errorf("failed to write nonce: %w", err)
	}

	// Encrypt all buffered data at once
	encrypted := gcm.Seal(nil, nonce, ew.buffer, nil)

	// Write encrypted data
	if _, err := ew.writer.Write(encrypted); err != nil {
		return fmt.Errorf("failed to write encrypted data: %w", err)
	}

	return nil
}

// Decryption reader remains the same
func createDecryptionReader(r io.Reader, password string) (io.Reader, error) {
	// Read salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, fmt.Errorf("failed to read salt: %w", err)
	}

	// Derive key
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Read nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %w", err)
	}

	// Read all encrypted data
	encryptedData, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}

	// Decrypt all data at once
	decryptedData, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return strings.NewReader(string(decryptedData)), nil
}

// Functional approach with defer
func WithEncryptedWriter(w io.Writer, password string, fn func(io.Writer) error) error {
	encWriter, err := CreateStreamingEncryptionWriter(w, password)
	if err != nil {
		return err
	}

	return fn(encWriter)
}

// Streaming encryption writer (encrypts data as it comes)
type StreamingEncryptionWriter struct {
	writer    io.Writer
	stream    cipher.Stream
	initiated bool
	password  string
}

func CreateStreamingEncryptionWriter(w io.Writer, password string) (*StreamingEncryptionWriter, error) {
	return &StreamingEncryptionWriter{
		writer:    w,
		password:  password,
		initiated: false,
	}, nil
}

func (sw *StreamingEncryptionWriter) Write(data []byte) (int, error) {
	if !sw.initiated {
		if err := sw.initStream(); err != nil {
			return 0, err
		}
		sw.initiated = true
	}

	encrypted := make([]byte, len(data))
	sw.stream.XORKeyStream(encrypted, data)

	return sw.writer.Write(encrypted)
}

func (sw *StreamingEncryptionWriter) initStream() error {
	// Generate salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Write salt
	if _, err := sw.writer.Write(salt); err != nil {
		return fmt.Errorf("failed to write salt: %w", err)
	}

	// Derive key
	key := pbkdf2.Key([]byte(sw.password), salt, 100000, 32, sha256.New)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return fmt.Errorf("failed to generate IV: %w", err)
	}

	// Write IV
	if _, err := sw.writer.Write(iv); err != nil {
		return fmt.Errorf("failed to write IV: %w", err)
	}

	// Create stream cipher
	sw.stream = cipher.NewCFBEncrypter(block, iv)

	return nil
}

// Streaming mode. Not secure as the above but work for large (multi GB files)
type AESCTRWriter struct {
	writer   io.Writer
	stream   cipher.Stream
	initOnce sync.Once
	password string
	err      error
}

func NewAESCTRWriter(w io.Writer, password string) *AESCTRWriter {
	return &AESCTRWriter{
		writer:   w,
		password: password,
	}
}

func (w *AESCTRWriter) init() {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		w.err = err
		return
	}

	if _, err := w.writer.Write(salt); err != nil {
		w.err = err
		return
	}

	key := pbkdf2.Key([]byte(w.password), salt, 100_000, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		w.err = err
		return
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		w.err = err
		return
	}

	if _, err := w.writer.Write(iv); err != nil {
		w.err = err
		return
	}

	w.stream = cipher.NewCTR(block, iv)
}

func (w *AESCTRWriter) Write(p []byte) (int, error) {
	w.initOnce.Do(w.init)
	if w.err != nil {
		return 0, w.err
	}

	buf := make([]byte, len(p))
	w.stream.XORKeyStream(buf, p)
	return w.writer.Write(buf)
}

type AESCTRReader struct {
	reader io.ReadCloser // the underlying source, e.g. file
	stream cipher.Stream // AES-CTR stream
	// buffer []byte        // buffer for decryption
}

// NewAESCTRReader creates a reader that decrypts as data is read.
func NewAESCTRReader(r io.ReadCloser, password string) (io.ReadCloser, error) {
	// Read salt (16 bytes)
	salt := make([]byte, 16)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, fmt.Errorf("failed to read salt: %w", err)
	}

	// Derive encryption key
	key := pbkdf2.Key([]byte(password), salt, 100_000, 32, sha256.New)

	// Initialize AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Read IV (AES block size, 16 bytes)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(r, iv); err != nil {
		return nil, fmt.Errorf("failed to read IV: %w", err)
	}

	// Create CTR stream
	stream := cipher.NewCTR(block, iv)

	return &AESCTRReader{
		reader: r,
		stream: stream,
	}, nil
}

// Read reads encrypted data, decrypts it, and writes plaintext to p
func (a *AESCTRReader) Read(p []byte) (int, error) {
	n, err := a.reader.Read(p)
	if n > 0 {
		a.stream.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

// Close closes the underlying reader
func (a *AESCTRReader) Close() error {
	return a.reader.Close()
}

func DecryptFile(inFile, outFile string, password string) error {
	f, err := os.Open(inFile)
	if err != nil {
		return err
	}
	defer f.Close()

	r, err := NewAESCTRReader(f, password)
	if err != nil {
		return err
	}
	defer r.Close() // this closes the file

	inf, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer inf.Close()
	_, err = io.Copy(inf, r)
	return err
}

func EncryptFile(inFile, outFile, password string) error {
	outFH, err := os.Create(outFile)
	if err != nil {
		return err
	}
	encWriter := NewAESCTRWriter(outFH, password)
	infile, err := os.Open(inFile)
	if err != nil {
		return err
	}
	_, err = io.Copy(encWriter, infile)
	return err
}
