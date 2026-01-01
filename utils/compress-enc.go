package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
)

// This operates on one file input and one output file. Take input, compress it, encrypt it and write to output. The extract does the inverse
//
// Support input as stdin or named pipe for streaming ops. My main purpose is to avoid big temp file but streamming from other pipe and send it out to other consumer as well
//
// This is usefull as tar can not get input data from stdin due to its specs
// The only other options is to use cpio format but go implementation of it seems to be buggy

// CompEncOptions holds configuration for cpio archive creation
type CompEncOptions struct {
	UseCompression    bool
	CompressionLevel  int
	Encrypt           bool
	Password          string
	EncryptMode       EncryptMode // "GCM" or "CTR"
	OverwriteExisting bool
}

// NewCompEncOptions returns default options for cpio creation
func NewCompEncOptions() *CompEncOptions {
	return &CompEncOptions{
		UseCompression:    true,
		CompressionLevel:  3,
		Encrypt:           true,
		EncryptMode:       EncryptModeCTR,
		OverwriteExisting: false,
		Password:          "",
	}
}

func (zo *CompEncOptions) WithCompressionLevel(level int) *CompEncOptions {
	zo.CompressionLevel = level
	return zo
}
func (zo *CompEncOptions) WithEncrypt(enabled bool) *CompEncOptions {
	zo.Encrypt = enabled
	return zo
}
func (zo *CompEncOptions) WithCompression(enabled bool) *CompEncOptions {
	zo.UseCompression = enabled
	return zo
}
func (zo *CompEncOptions) WithPassword(pass string) *CompEncOptions {
	zo.Password = pass
	return zo
}
func (zo *CompEncOptions) WithEncryptMode(m EncryptMode) *CompEncOptions {
	zo.EncryptMode = m
	return zo
}

func (zo *CompEncOptions) WithOverwriteExisting(s bool) *CompEncOptions {
	zo.OverwriteExisting = s
	return zo
}

// CreateCompEncArchive creates an archive with streaming support for stdin/FIFOs
// Accepts either a string or io.ReadCloser for sources
// If source is "-" or a FIFO file, reads from stdin/fifo
func CreateCompEncArchive(source, outputPath any, options *CompEncOptions) error {
	if outputPath == nil {
		return fmt.Errorf("output path cannot be nil")
	}

	if options == nil {
		options = NewCompEncOptions()
	}

	// Prepare output
	var outputFile = Must(processOutputFile(outputPath, options.OverwriteExisting))
	defer outputFile.Close()
	var writer io.Writer = outputFile

	// Encryption
	if options.Encrypt {
		var err error
		if options.Password == "" {
			return fmt.Errorf("password is required for encryption")
		}
		var ew io.WriteCloser
		switch options.EncryptMode {
		case EncryptModeGCM:
			ew = CreateEncryptionWriter(writer, options.Password)
			if ew == nil {
				return fmt.Errorf("failed to create encryption writer")
			}
			defer ew.Close()
		case EncryptModeCTR:
			ew, err = NewStreamEncryptWriter(writer, options.Password)
			if err != nil {
				return fmt.Errorf("failed to create encryption writer - %v", err)
			}
			defer ew.Close()
		}
		writer = ew
	}

	// Compression
	if options.UseCompression {
		zw, err := zstd.NewWriter(writer, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(options.CompressionLevel)))
		if err != nil {
			return fmt.Errorf("failed to create zstd writer: %w", err)
		}
		defer zw.Close()
		writer = zw
	}

	// source = filepath.Clean(source)

	var reader io.Reader
	switch v := source.(type) {
	case string:
		switch v {
		case "-":
			reader = os.Stdin
		default:
			source1 := filepath.Clean(v)
			f := MustOpenFile(source1)
			defer f.Close()
			reader = f
			defer f.Close()
		}
	case io.Reader:
		reader = v
	default:
		return fmt.Errorf("[ERROR] source must be string or io.Reader")
	}

	written, err := io.Copy(writer, reader)
	if err != nil {
		return fmt.Errorf("failed to stream stdin: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[INFO] written %d bytes\n", written)
	return nil

}

// ExtractCompEncArchive extracts a cpio archive with support for compression and encryption
// If inputPath is "-", reads from stdin
func ExtractCompEncArchive(inputPath, outputPath any, options *CompEncOptions) error {
	if options == nil {
		options = NewCompEncOptions()
	}

	// Prepare input
	var inputFile io.ReadCloser
	var err error
	switch v := inputPath.(type) {
	case string:
		switch v {
		case "-":
			inputFile = os.Stdin
		default:
			inputFile, err = os.Open(v)
			if err != nil {
				return fmt.Errorf("failed to open input file: %w", err)
			}
		}
	case io.ReadCloser:
		inputFile = v
	default:
		return fmt.Errorf("[ERROR] source must be string or io.ReadCloser")
	}
	defer inputFile.Close()

	var reader io.Reader = inputFile

	// Decryption
	if options.Encrypt {
		if options.Password == "" {
			return fmt.Errorf("password is required for decryption")
		}
		var dr io.Reader
		switch options.EncryptMode {
		case EncryptModeGCM:
			dr = Must(CreateDecryptionReader(inputFile, options.Password))
			if dr == nil {
				return fmt.Errorf("failed to create decryption reader")
			}

		case EncryptModeCTR:
			dr, err = NewStreamDecryptReader(inputFile, options.Password)
			if err != nil {
				return fmt.Errorf("failed to create decryption reader - %v", err)
			}

		}
		reader = dr
	}

	// Decompression
	if options.UseCompression {
		zr, err := zstd.NewReader(reader)
		if err != nil {
			return fmt.Errorf("failed to create zstd reader: %w", err)
		}
		defer zr.Close()
		reader = zr
	}

	// Extract files
	var outputFile = Must(processOutputFile(outputPath, options.OverwriteExisting))
	defer outputFile.Close()
	Must(io.Copy(outputFile, reader))
	return nil
}

// remember to close
func processOutputFile(outputPath any, overwrite bool) (outputFile io.WriteCloser, err error) {
	switch v := outputPath.(type) {
	case string:
		switch {
		case v == "-":
			outputFile = os.Stdout
		default:
			switch {
			case GetFirstValue(IsNamedPipe(v)):
				outputFile, err = os.OpenFile(v, os.O_WRONLY|os.O_CREATE, 0666)
				if err != nil {
					return nil, err
				}
			case Exists(v) && !overwrite:
				panic("[ERROR] Output file exists\n")
			default:
				outputFile, err = os.Create(v)
				if err != nil {
					return nil, fmt.Errorf("failed to create output file: %w", err)
				}
			}
		}
	case io.WriteCloser:
		outputFile = v
	default:
		return nil, fmt.Errorf("[ERROR] source must be string or io.WriteCloser")
	}
	return
}
