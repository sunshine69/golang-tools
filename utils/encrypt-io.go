package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

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
	key := pbkdf2.Key([]byte(ew.password), salt, 350000, 32, sha256.New)

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
	key := pbkdf2.Key([]byte(password), salt, 350000, 32, sha256.New)

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

// AES CTR IO
const (
	magic        = "AESC1CTR" // 8 bytes
	version      = uint8(1)   // 1 byte
	saltSize     = 16
	ivSize       = aes.BlockSize // 16
	keySize      = 32            // AES-256
	macSize      = 32            // HMAC-SHA256
	defaultIter  = 310_000       // PBKDF2 iterations
	defaultFrame = 16 * 1024     // 16 KiB default frame size (small for streaming)
)

var (
	ErrMacMismatch = fmt.Errorf("authentication failed: HMAC mismatch")
	ErrBadHeader   = fmt.Errorf("bad header")
)

// Header layout:
// [magic 8][version 1][salt 16][iv 16][iter 4 BE][frameSize 4 BE]
// total = 49 bytes
func writeHeader(w io.Writer, salt, iv []byte, iter uint32, frameSize uint32) error {
	var buf [9]byte
	copy(buf[:8], []byte(magic))
	buf[8] = byte(version)
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	if _, err := w.Write(salt); err != nil {
		return err
	}
	if _, err := w.Write(iv); err != nil {
		return err
	}
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], iter)
	if _, err := w.Write(tmp[:]); err != nil {
		return err
	}
	binary.BigEndian.PutUint32(tmp[:], frameSize)
	_, err := w.Write(tmp[:])
	return err
}

func readHeader(r io.Reader) (salt, iv []byte, iter uint32, frameSize uint32, err error) {
	hdr := make([]byte, 9)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return
	}
	if string(hdr[:8]) != magic || hdr[8] != byte(version) {
		err = ErrBadHeader
		return
	}
	salt = make([]byte, saltSize)
	if _, err = io.ReadFull(r, salt); err != nil {
		return
	}
	iv = make([]byte, ivSize)
	if _, err = io.ReadFull(r, iv); err != nil {
		return
	}
	var tmp [4]byte
	if _, err = io.ReadFull(r, tmp[:]); err != nil {
		return
	}
	iter = binary.BigEndian.Uint32(tmp[:])
	if _, err = io.ReadFull(r, tmp[:]); err != nil {
		return
	}
	frameSize = binary.BigEndian.Uint32(tmp[:])
	return
}

// ---------------- Writer ----------------

// StreamEncryptWriter implements io.WriteCloser
type StreamEncryptWriter struct {
	w         io.Writer
	frameSize int
	iter      uint32

	// runtime
	block  cipher.Block
	stream cipher.Stream
	macKey []byte
	seq    uint64

	buf []byte // plaintext buffer for current frame (len <= frameSize)
	h   func() hash.Hash

	closed bool
}

// StreamEncryptOption helpers
type StreamEncryptOpt func(*StreamEncryptWriter)

func WithPBKDF2Iter(i uint32) StreamEncryptOpt {
	return func(s *StreamEncryptWriter) { s.iter = i }
}

func WithFrameSize(sz int) StreamEncryptOpt {
	return func(s *StreamEncryptWriter) { s.frameSize = sz }
}

// NewStreamEncryptWriter writes a header then streams framed ciphertext+tag.
// MUST call Close() to flush any final partial frame.
func NewStreamEncryptWriter(w io.Writer, password string, opts ...StreamEncryptOpt) (*StreamEncryptWriter, error) {
	s := &StreamEncryptWriter{
		w:         w,
		frameSize: defaultFrame,
		iter:      defaultIter,
		h:         sha256.New,
	}

	for _, o := range opts {
		o(s)
	}
	if s.frameSize <= 0 {
		s.frameSize = defaultFrame
	}

	// build header (salt + iv) and derive keys
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	iv := make([]byte, ivSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// derive 64 bytes: AES key || MAC key
	derived := pbkdf2.Key([]byte(password), salt, int(s.iter), keySize*2, s.h)
	block, err := aes.NewCipher(derived[:keySize])
	if err != nil {
		// zero derived before returning
		for i := range derived {
			derived[i] = 0
		}
		return nil, err
	}
	s.block = block
	s.macKey = make([]byte, keySize)
	copy(s.macKey, derived[keySize:])

	// wipe derived & password
	for i := range derived {
		derived[i] = 0
	}
	// best effort wipe password bytes
	pw := []byte(password)
	for i := range pw {
		pw[i] = 0
	}

	// initialize CTR stream
	s.stream = cipher.NewCTR(s.block, iv)
	s.buf = make([]byte, 0, s.frameSize)

	// write header
	if err := writeHeader(s.w, salt, iv, s.iter, uint32(s.frameSize)); err != nil {
		return nil, err
	}
	return s, nil
}

// Write buffers up to frameSize; when full it encrypts+tags+writes a frame.
// It returns number of bytes consumed from p or an error.
func (s *StreamEncryptWriter) Write(p []byte) (int, error) {
	if s.closed {
		return 0, fmt.Errorf("write after close")
	}
	total := 0
	for len(p) > 0 {
		space := s.frameSize - len(s.buf)
		if space > len(p) {
			space = len(p)
		}
		s.buf = append(s.buf, p[:space]...)
		p = p[space:]
		total += space

		if len(s.buf) == s.frameSize {
			if err := s.flushFrame(); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

// flushFrame encrypts current buf and writes [len][ciphertext][tag]
func (s *StreamEncryptWriter) flushFrame() error {
	if len(s.buf) == 0 {
		return nil
	}

	// encrypt (do not modify s.buf in-place to avoid surprising caller)
	ct := make([]byte, len(s.buf))
	s.stream.XORKeyStream(ct, s.buf)

	// compute HMAC(seq || ciphertext)
	mac := hmac.New(s.h, s.macKey)
	var seqb [8]byte
	binary.BigEndian.PutUint64(seqb[:], s.seq)
	mac.Write(seqb[:])
	mac.Write(ct)
	tag := mac.Sum(nil)

	// frame length (uint32 BE)
	var lenb [4]byte
	binary.BigEndian.PutUint32(lenb[:], uint32(len(ct)))
	if _, err := s.w.Write(lenb[:]); err != nil {
		return err
	}
	if _, err := s.w.Write(ct); err != nil {
		return err
	}
	if _, err := s.w.Write(tag); err != nil {
		return err
	}

	// advance
	s.seq++
	// reset buffer reusing capacity
	s.buf = s.buf[:0]
	return nil
}

// Close flushes final partial frame and attempts to close underlying if it is a Closer.
func (s *StreamEncryptWriter) Close() error {
	if s.closed {
		return nil
	}
	if err := s.flushFrame(); err != nil {
		return err
	}
	s.closed = true
	if closer, ok := s.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// ---------------- Reader ----------------

// StreamDecryptReader implements io.ReadCloser
type StreamDecryptReader struct {
	r         io.ReadCloser
	stream    cipher.Stream
	macKey    []byte
	seq       uint64
	frameSize int

	outBuf *bytes.Buffer // decrypted data queue
	h      func() hash.Hash
}

// NewStreamDecryptReader reads header and returns a reader that yields plaintext.
// It validates per-frame HMACs and returns ErrMacMismatch if tampered.
func NewStreamDecryptReader(rc io.ReadCloser, password string) (io.ReadCloser, error) {
	salt, iv, iter, frameSize, err := readHeader(rc)
	if err != nil {
		return nil, err
	}
	if frameSize == 0 {
		return nil, fmt.Errorf("invalid frame size")
	}

	derived := pbkdf2.Key([]byte(password), salt, int(iter), keySize*2, sha256.New)
	block, err := aes.NewCipher(derived[:keySize])
	if err != nil {
		for i := range derived {
			derived[i] = 0
		}
		return nil, err
	}
	macKey := make([]byte, keySize)
	copy(macKey, derived[keySize:])
	for i := range derived {
		derived[i] = 0
	}

	r := &StreamDecryptReader{
		r:         rc,
		stream:    cipher.NewCTR(block, iv),
		macKey:    macKey,
		frameSize: int(frameSize),
		outBuf:    bytes.NewBuffer(nil),
		h:         sha256.New,
	}
	return r, nil
}

// Read returns decrypted plaintext, verifying each frame before returning its bytes.
func (s *StreamDecryptReader) Read(p []byte) (int, error) {
	// if we already have decrypted bytes, serve them first
	if s.outBuf.Len() > 0 {
		return s.outBuf.Read(p)
	}

	// read frame length
	var lenb [4]byte
	if _, err := io.ReadFull(s.r, lenb[:]); err != nil {
		return 0, err // EOF or other
	}
	frameLen := binary.BigEndian.Uint32(lenb[:])
	if frameLen == 0 {
		return 0, io.EOF
	}
	if int(frameLen) > s.frameSize*10 { // sanity check (allow some slack)
		return 0, fmt.Errorf("frame too large")
	}

	// read ciphertext
	ct := make([]byte, frameLen)
	if _, err := io.ReadFull(s.r, ct); err != nil {
		return 0, err
	}
	// read tag
	tag := make([]byte, macSize)
	if _, err := io.ReadFull(s.r, tag); err != nil {
		return 0, err
	}

	// verify HMAC(seq || ct)
	mac := hmac.New(s.h, s.macKey)
	var seqb [8]byte
	binary.BigEndian.PutUint64(seqb[:], s.seq)
	mac.Write(seqb[:])
	mac.Write(ct)
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, tag) {
		return 0, ErrMacMismatch
	}

	// decrypt
	plain := make([]byte, len(ct))
	s.stream.XORKeyStream(plain, ct)
	s.seq++

	// queue and serve
	s.outBuf.Write(plain)
	return s.outBuf.Read(p)
}

func (s *StreamDecryptReader) Close() error {
	return s.r.Close()
}

// End stream IO

// Utility functions
func DecryptFile(inFile, outFile string, password string) error {
	var inputF io.ReadCloser
	var err error
	switch inFile {
	case "-":
		inputF = os.Stdin
	default:
		inputF, err = os.Open(inFile)
		if err != nil {
			return err
		}
		defer inputF.Close()
	}

	r, err := NewStreamDecryptReader(inputF, password)
	if err != nil {
		return err
	}
	defer r.Close() // this closes the file

	var inf io.WriteCloser
	switch outFile {
	case "-":
		inf = os.Stdout
	default:
		inf, err = os.Create(outFile)
		if err != nil {
			return err
		}
		defer inf.Close()
	}
	_, err = io.Copy(inf, r)
	return err
}

func EncryptFile(inFile, outFile, password string) error {
	var outFH io.Writer
	var err error
	switch outFile {
	case "-":
		outFH = os.Stdout
	default:
		outFH, err = os.Create(outFile)
		if err != nil {
			return err
		}
	}
	encWriter, err := NewStreamEncryptWriter(outFH, password)
	if err != nil {
		return err
	}
	defer encWriter.Close()
	var infile io.ReadCloser
	switch inFile {
	case "-":
		infile = os.Stdin
	default:
		infile, err = os.Open(inFile)
		if err != nil {
			return err
		}
	}
	_, err = io.Copy(encWriter, infile)
	return err
}
