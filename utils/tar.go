package utils

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/klauspost/compress/zstd"
)

// TarOptions contains configuration for the tar creation
type TarOptions struct {
	UseCompression   bool
	Encrypt          bool
	EncryptMode      EncryptMode
	Password         string
	CompressionLevel int  // 1-22 for zstd, default is 3
	StripTopLevelDir bool // New option: true = remove top-level folder from tar paths
}

func NewTarOptions() *TarOptions {
	return &TarOptions{
		UseCompression:   true,
		CompressionLevel: 3, // default is 3, mine use 15 and seems good - 19 too slow
		Encrypt:          false,
		EncryptMode:      EncryptModeCTR,
		Password:         "",
		StripTopLevelDir: false,
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
func (zo *TarOptions) WithEncryptMode(m EncryptMode) *TarOptions {
	zo.EncryptMode = m
	return zo
}
func (zo *TarOptions) WithStripTopLevelDir(s bool) *TarOptions {
	zo.StripTopLevelDir = s
	return zo
}

func CreateTarball(sources interface{}, outputPath string, options *TarOptions) error {
	// Validate output path
	if outputPath == "" {
		return fmt.Errorf("output path cannot be empty")
	}

	// Normalize input into a slice of file paths
	var fileList []string
	switch v := sources.(type) {
	case string:
		fileList = []string{v}
	case []string:
		if len(v) == 0 {
			return fmt.Errorf("no source files provided")
		}
		fileList = v
	default:
		return fmt.Errorf("sources must be a string or []string")
	}

	// Verify each source exists
	for _, f := range fileList {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			return fmt.Errorf("source path does not exist: %s", f)
		}
	}

	if options == nil {
		options = NewTarOptions()
	}

	// Create output file or use stdout
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

	// Encryption layer
	if options.Encrypt {
		if options.Password == "" {
			return fmt.Errorf("password is required for encryption")
		}
		var encryptedWriter io.WriteCloser
		switch options.EncryptMode {
		case EncryptModeGCM:
			encryptedWriter = CreateEncryptionWriter(writer, options.Password)
			if encryptedWriter == nil {
				return fmt.Errorf("failed to create encryption writer")
			}
			defer encryptedWriter.Close()
		case EncryptModeCTR:
			encryptedWriter, err = NewStreamEncryptWriter(writer, options.Password)
			if err != nil {
				return fmt.Errorf("failed to create encryption writer - " + err.Error())
			}
			defer encryptedWriter.Close()
		}
		writer = encryptedWriter
	}

	// Compression layer
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

	// Tar writer
	tarWriter := tar.NewWriter(writer)
	defer tarWriter.Close()

	// Iterate over each source file/directory
	for _, source := range fileList {
		source = filepath.Clean(source)

		info, err := os.Stat(source)
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", source, err)
		}

		if info.IsDir() {
			// Directory: walk recursively
			err = filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				var relPath string
				if options.StripTopLevelDir {
					relPath, err = filepath.Rel(source, path) // Strip top-level dir
				} else {
					relPath, err = filepath.Rel(filepath.Dir(source), path) // Keep top-level dir
				}
				if err != nil {
					return fmt.Errorf("failed to get relative path: %w", err)
				}

				// Skip empty string (root dir entry when stripping)
				if relPath == "." {
					return nil
				}

				tarPath := filepath.ToSlash(relPath)

				linkTarget := ""
				if info.Mode()&os.ModeSymlink != 0 {
					linkTarget, err = os.Readlink(path)
					if err != nil {
						return fmt.Errorf("failed to read symlink target for %s: %w", path, err)
					}
				}

				header, err := tar.FileInfoHeader(info, linkTarget)
				if err != nil {
					if runtime.GOOS == "windows" {
						fmt.Fprintf(os.Stderr, "[WARN] enforcing file permission for %s\n", tarPath)
						header = &tar.Header{
							Name:    tarPath,
							Size:    info.Size(),
							Mode:    0644,
							ModTime: info.ModTime(),
						}
					} else {
						return fmt.Errorf("failed to create tar header for %s: %w", path, err)
					}
				}
				header.Name = tarPath

				if err := tarWriter.WriteHeader(header); err != nil {
					return fmt.Errorf("failed to write tar header: %w", err)
				}

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
				return err
			}
		} else {
			// Single file: always just the base name
			linkTarget := ""
			if info.Mode()&os.ModeSymlink != 0 {
				linkTarget, err = os.Readlink(source)
				if err != nil {
					return fmt.Errorf("failed to read symlink target for %s: %w", source, err)
				}
			}

			header, err := tar.FileInfoHeader(info, linkTarget)
			if err != nil {
				if runtime.GOOS == "windows" {
					fmt.Fprintf(os.Stderr, "[WARN] enforcing file permission for %s\n", filepath.Base(source))
					header = &tar.Header{
						Name:    filepath.Base(source),
						Size:    info.Size(),
						Mode:    0644,
						ModTime: info.ModTime(),
					}
				} else {
					return fmt.Errorf("failed to create tar header for %s: %w", source, err)
				}
			}
			header.Name = filepath.Base(source)

			if err := tarWriter.WriteHeader(header); err != nil {
				return fmt.Errorf("failed to write tar header: %w", err)
			}

			if info.Mode().IsRegular() {
				file, err := os.Open(source)
				if err != nil {
					return fmt.Errorf("failed to open file %s: %w", source, err)
				}
				defer file.Close()

				if _, err := io.Copy(tarWriter, file); err != nil {
					return fmt.Errorf("failed to write file content: %w", err)
				}
			}
		}
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
		var decryptedReader io.Reader
		var err error
		switch options.EncryptMode {
		case EncryptModeGCM:
			decryptedReader, err = CreateDecryptionReader(file, options.Password)
			if err != nil {
				return fmt.Errorf("failed to create decryption reader GCM: %w", err)
			}
		case EncryptModeCTR:
			decryptedReader, err = NewStreamDecryptReader(file, options.Password)
			if err != nil {
				return fmt.Errorf("failed to create decryption reader CTR: %w", err)
			}
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
