package utils

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
)

// TarOptions contains configuration for the tar creation
type TarOptions struct {
	UseCompression   bool
	Encrypt          bool
	Password         string
	CompressionLevel int // 1-22 for zstd, default is 3
}

func NewTarOptions() *TarOptions {
	return &TarOptions{
		UseCompression:   true,
		CompressionLevel: 3, // default is 3, mine use 15 and seems good - 19 too slow
		Encrypt:          false,
		Password:         "",
	}
}
func (zo *TarOptions) WithCompressionLevel(level int) *TarOptions {
	zo.CompressionLevel = level
	return zo
}
func (zo *TarOptions) WithEncrypt(enabled bool) *TarOptions {
	zo.Encrypt = enabled
	return zo
}
func (zo *TarOptions) EnableCompression(enabled bool) *TarOptions {
	zo.UseCompression = enabled
	return zo
}
func (zo *TarOptions) WithPassword(pass string) *TarOptions {
	zo.Password = pass
	return zo
}

func CreateTarball(sourceDir, outputPath string, options *TarOptions) error {
	// Validate inputs
	if sourceDir == "" || outputPath == "" {
		return fmt.Errorf("source directory and output path cannot be empty")
	}

	// Check if source directory exists
	if _, err := os.Stat(sourceDir); os.IsNotExist(err) {
		return fmt.Errorf("source directory does not exist: %s", sourceDir)
	}
	if options == nil {
		options = NewTarOptions()
	}
	// Create output file
	var outputFile io.WriteCloser
	var err error
	switch outputPath {
	case "-":
		outputFile = os.Stdout
	default:
		outputFile, err = os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer outputFile.Close()
	}

	var writer io.Writer = outputFile

	// Add encryption layer if requested
	if options.Encrypt {
		if options.Password == "" {
			return fmt.Errorf("password is required for encryption")
		}
		encryptedWriter := NewAESCTRWriter(writer, options.Password)
		if encryptedWriter == nil {
			return fmt.Errorf("failed to create encryption writer")
		}
		// defer encryptedWriter.Close()
		writer = encryptedWriter
	}

	// Add compression layer if requested
	if options.UseCompression {
		level := options.CompressionLevel
		if level == 0 {
			level = 3 // Default compression level
		}

		zstdWriter, err := zstd.NewWriter(writer, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)))
		if err != nil {
			return fmt.Errorf("failed to create zstd writer: %w", err)
		}
		defer zstdWriter.Close()
		writer = zstdWriter
	}

	// Create tar writer
	tarWriter := tar.NewWriter(writer)
	defer tarWriter.Close()

	// Get the base directory name (e.g., "gitlab")
	baseName := filepath.Base(sourceDir)

	// Walk through the source directory and add files to tar
	err = filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Determine the relative path and include top-level directory
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}
		tarPath := filepath.ToSlash(filepath.Join(baseName, relPath))

		// Handle symlinks correctly by providing the link target
		linkTarget := ""
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err = os.Readlink(path)
			if err != nil {
				return fmt.Errorf("failed to read symlink target for %s: %w", path, err)
			}
		}

		// Create tar header
		header, err := tar.FileInfoHeader(info, linkTarget)
		if err != nil {
			return fmt.Errorf("failed to create tar header for %s: %w", path, err)
		}
		header.Name = tarPath

		// Write header to tar
		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write tar header: %w", err)
		}

		// If it's a regular file, copy content
		if info.Mode().IsRegular() {
			file, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("failed to open file %s: %w", path, err)
			}
			defer file.Close()

			if _, err := io.Copy(tarWriter, file); err != nil {
				return fmt.Errorf("failed to write file content: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to create tarball: %w", err)
	}

	return nil
}

// ExtractTarball extracts a tarball with optional decompression and decryption
func ExtractTarball(tarballPath, extractDir string, options *TarOptions) error {
	var file io.ReadCloser
	var err error
	switch tarballPath {
	case "-":
		file = os.Stdin
	default:
		// Open the tarball file
		file, err = os.Open(tarballPath)
		if err != nil {
			return fmt.Errorf("failed to open tarball: %w", err)
		}
		defer file.Close()
	}
	var reader io.Reader = file

	// Add decryption layer if needed
	if options.Encrypt {
		if options.Password == "" {
			return fmt.Errorf("password is required for decryption")
		}

		decryptedReader, err := NewAESCTRReader(file, options.Password)
		if err != nil {
			return fmt.Errorf("failed to create decryption reader: %w", err)
		}
		reader = decryptedReader
	}

	// Add decompression layer if needed
	if options.UseCompression {
		zstdReader, err := zstd.NewReader(reader)
		if err != nil {
			return fmt.Errorf("failed to create zstd reader: %w", err)
		}
		defer zstdReader.Close()
		reader = zstdReader
	}

	// Create tar reader
	tarReader := tar.NewReader(reader)

	// Extract files
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Create the full path
		path := filepath.Join(extractDir, header.Name)

		// Handle different file types
		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory
			if err := os.MkdirAll(path, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", path, err)
			}
		case tar.TypeReg:
			// Create parent directories
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return fmt.Errorf("failed to create parent directories for %s: %w", path, err)
			}

			// Create and write file
			outFile, err := os.Create(path)
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", path, err)
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to write file content: %w", err)
			}

			outFile.Close()

			// Set file permissions
			if err := os.Chmod(path, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to set file permissions: %w", err)
			}
		}
	}

	return nil
}
