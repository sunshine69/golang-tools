package utils

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Zip works and tested on linux and windows

// ZipOptions contains configuration for ZIP creation
type ZipOptions struct {
	UseCompression   bool
	CompressionLevel int // 0-9 for ZIP, -1 for default
	// Use GCM only as Zipreader requires fixed block in reader. To handle large file, disable encryption, write to temporary file, then call stream CTR encryption to convert the file at the caller side
	Encrypt  bool
	Password string
}

func NewZipOptions() *ZipOptions {
	return &ZipOptions{
		UseCompression:   true,
		CompressionLevel: 6,
		Encrypt:          false,
		Password:         "",
	}
}
func (zo *ZipOptions) WithCompressionLevel(level int) *ZipOptions {
	zo.CompressionLevel = level
	return zo
}
func (zo *ZipOptions) WithEncrypt(enabled bool) *ZipOptions {
	zo.Encrypt = enabled
	return zo
}
func (zo *ZipOptions) EnableCompression(enabled bool) *ZipOptions {
	zo.UseCompression = enabled
	return zo
}
func (zo *ZipOptions) WithPassword(pass string) *ZipOptions {
	zo.Password = pass
	return zo
}

// CreateZipArchive creates a ZIP archive using default options. Support encryption but not zip encryption.
// Rather a string AES encryption layer however that means if you enable encryption, you have to use the ExtractZipArchive func here to
// extract. All zip tool wont be able to extract it.
// Default option set encryption to false thus zip archive can be extracted by other standard zip
func CreateZipArchive(sourceDir, outputPath string, options *ZipOptions) error {
	// Validate inputs
	if sourceDir == "" || outputPath == "" {
		return fmt.Errorf("source directory and output path cannot be empty")
	}

	// Check if source directory exists
	if _, err := os.Stat(sourceDir); os.IsNotExist(err) {
		return fmt.Errorf("source directory does not exist: %s", sourceDir)
	}
	if options == nil {
		options = NewZipOptions()
	}
	// Create output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	var writer io.Writer = outputFile

	// Add encryption layer if requested
	if options.Encrypt {
		if options.Password == "" {
			return fmt.Errorf("password is required for encryption")
		}

		encryptedWriter := CreateEncryptionWriter(writer, options.Password)
		defer encryptedWriter.Close()
		writer = encryptedWriter
	}

	// Create ZIP writer
	zipWriter := zip.NewWriter(writer)
	defer zipWriter.Close()

	// Set compression method
	if options.UseCompression {
		// ZIP uses deflate compression by default
	}

	// Walk through the source directory and add files to ZIP
	err = filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// On Windows, skip files we can't access rather than failing
			if runtime.GOOS == "windows" {
				fmt.Printf("Warning: Skipping inaccessible file: %s (%v)\n", path, err)
				return nil
			}
			return err
		}

		// Skip Windows system files
		if isWindowsSystemFile(path) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Determine path inside ZIP
		var zipPath string

		// Match 'zip' CLI behavior: if sourceDir is absolute, keep full path minus leading slash
		if filepath.IsAbs(sourceDir) {
			if runtime.GOOS == "windows" {
				volume := filepath.VolumeName(path)
				zipPath = strings.TrimPrefix(path, volume+string(filepath.Separator)) // removes leading 'C:'
			} else {
				zipPath = strings.TrimPrefix(path, string(filepath.Separator)) // removes leading '/'
			}
		} else {
			// Default: use path relative to sourceDir
			baseName := filepath.Base(sourceDir)

			relPath, err := filepath.Rel(sourceDir, path)
			if err != nil {
				return fmt.Errorf("failed to get relative path: %w", err)
			}
			zipPath = filepath.Join(baseName, relPath)

		}

		// Normalize path to use forward slashes
		zipPath = filepath.ToSlash(zipPath)

		// Skip the root directory entry
		if zipPath == "." {
			return nil
		}

		// Handle directories
		if info.IsDir() {
			// Add trailing slash for directories in ZIP format
			if !strings.HasSuffix(zipPath, "/") {
				zipPath += "/"
			}

			// Create directory entry
			_, err := zipWriter.Create(zipPath)
			return err
		}

		// Handle regular files
		if info.Mode().IsRegular() {
			// Create file header
			header := &zip.FileHeader{
				Name:               zipPath,
				Method:             zip.Deflate, // Use deflate compression
				Modified:           info.ModTime(),
				UncompressedSize64: uint64(info.Size()),
			}

			// Set compression method based on options
			if options.UseCompression {
				header.Method = zip.Deflate
			} else {
				header.Method = zip.Store // No compression
			}

			// Set file mode (Windows will ignore Unix permissions)
			header.SetMode(info.Mode())

			// Create file in ZIP
			zipFile, err := zipWriter.CreateHeader(header)
			if err != nil {
				return fmt.Errorf("failed to create ZIP file entry: %w", err)
			}

			// Open source file
			sourceFile, err := os.Open(path)
			if err != nil {
				if runtime.GOOS == "windows" {
					fmt.Printf("Warning: Cannot open file %s: %v\n", path, err)
					return nil
				}
				return fmt.Errorf("failed to open file %s: %w", path, err)
			}
			defer sourceFile.Close()

			// Copy file content
			if _, err := io.Copy(zipFile, sourceFile); err != nil {
				return fmt.Errorf("failed to write file content: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to create ZIP archive: %w", err)
	}

	return nil
}

// isWindowsSystemFile checks if a file should be skipped on Windows
func isWindowsSystemFile(path string) bool {
	if runtime.GOOS != "windows" {
		return false
	}

	lowerPath := strings.ToLower(path)
	systemPaths := []string{
		"system volume information",
		"$recycle.bin",
		"hiberfil.sys",
		"pagefile.sys",
		"swapfile.sys",
	}

	for _, sysPath := range systemPaths {
		if strings.Contains(lowerPath, sysPath) {
			return true
		}
	}

	// Check for desktop.ini files
	return strings.HasSuffix(lowerPath, "desktop.ini")
}

// ExtractZipArchive extracts a ZIP archive with optional decryption
func ExtractZipArchive(zipPath, extractDir string, options *ZipOptions) error {
	// Open the ZIP file
	file, err := os.Open(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open ZIP file: %w", err)
	}
	defer file.Close()

	var zipReader *zip.Reader
	if options == nil {
		options = &ZipOptions{
			UseCompression:   true,
			CompressionLevel: 5,
			Encrypt:          false,
		}
	}
	// Handle decryption if needed
	if options.Encrypt {
		if options.Password == "" {
			return fmt.Errorf("password is required for decryption")
		}

		decryptedReader, err := CreateDecryptionReader(file, options.Password)
		if err != nil {
			return fmt.Errorf("failed to create decryption reader: %w", err)
		}

		decryptedData, err := io.ReadAll(decryptedReader)
		if err != nil {
			return fmt.Errorf("failed to decrypt data: %w", err)
		}

		zipReader, err = zip.NewReader(strings.NewReader(string(decryptedData)), int64(len(decryptedData)))
		if err != nil {
			return fmt.Errorf("failed to create ZIP reader from decrypted data: %w", err)
		}
	} else {
		// Get file size for ZIP reader
		fileInfo, err := file.Stat()
		if err != nil {
			return fmt.Errorf("failed to get file info: %w", err)
		}

		// Create ZIP reader directly from file
		zipReader, err = zip.NewReader(file, fileInfo.Size())
		if err != nil {
			return fmt.Errorf("failed to create ZIP reader: %w", err)
		}
	}

	// Extract files
	for _, zipFile := range zipReader.File {
		// Create the full path
		path := filepath.Join(extractDir, zipFile.Name)

		// Ensure path is within extract directory (security check)
		if !strings.HasPrefix(path, filepath.Clean(extractDir)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid file path: %s", zipFile.Name)
		}

		// Check if it's a directory (ends with / or is marked as directory)
		isDir := strings.HasSuffix(zipFile.Name, "/") || zipFile.FileInfo().IsDir()

		if isDir {
			// Create directory with safe permissions
			dirMode := os.FileMode(0755) // Use safe default permissions
			if runtime.GOOS == "windows" {
				dirMode = 0755 // Windows ignores Unix permissions anyway
			}

			if err := os.MkdirAll(path, dirMode); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", path, err)
			}
			continue
		}

		// Create parent directories with safe permissions
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return fmt.Errorf("failed to create parent directories for %s: %w", path, err)
		}

		// Open file in ZIP
		zipFileReader, err := zipFile.Open()
		if err != nil {
			return fmt.Errorf("failed to open file in ZIP: %w", err)
		}

		// Create output file
		outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			zipFileReader.Close()
			return fmt.Errorf("failed to create output file %s: %w", path, err)
		}

		// Copy content
		_, err = io.Copy(outFile, zipFileReader)
		zipFileReader.Close()
		outFile.Close()

		if err != nil {
			return fmt.Errorf("failed to extract file %s: %w", path, err)
		}

		// Set file permissions only on Unix-like systems
		if runtime.GOOS != "windows" {
			fileMode := zipFile.FileInfo().Mode()
			// Ensure we have at least read permissions
			if fileMode&0400 == 0 {
				fileMode |= 0644 // Add read/write for owner, read for others
			}
			if err := os.Chmod(path, fileMode); err != nil {
				// Don't fail on permission errors, just warn
				fmt.Printf("Warning: failed to set permissions for %s: %v\n", path, err)
			}
		}
	}

	return nil
}
