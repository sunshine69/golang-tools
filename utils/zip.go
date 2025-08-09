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

// CreateZipArchive creates a ZIP archive from:
// - sourceDir: a directory path (string)
// - sources: multiple file/directory paths ([]string)
func CreateZipArchive(sources interface{}, outputPath string, options *ZipOptions) error {
	// Handle different input types
	switch v := sources.(type) {
	case string:
		// Single path - could be file or directory
		return createZipFromSinglePath(v, outputPath, options)
	case []string:
		// Multiple paths - files and/or directories
		return createZipFromMultiplePaths(v, outputPath, options)
	default:
		return fmt.Errorf("sources must be a string (single path) or []string (multiple paths)")
	}
}

// createZipFromSinglePath handles single file or directory
func createZipFromSinglePath(sourcePath, outputPath string, options *ZipOptions) error {
	// Validate inputs
	if sourcePath == "" || outputPath == "" {
		return fmt.Errorf("source path and output path cannot be empty")
	}

	// Check if source exists
	info, err := os.Stat(sourcePath)
	if os.IsNotExist(err) {
		return fmt.Errorf("source does not exist: %s", sourcePath)
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

	if info.IsDir() {
		// Handle directory - use original logic
		return walkAndAddDirectory(zipWriter, sourcePath, options)
	} else {
		// Handle single file
		return addSingleFileToZip(zipWriter, sourcePath, options)
	}
}

// createZipFromMultiplePaths handles multiple files and/or directories
func createZipFromMultiplePaths(sourcePaths []string, outputPath string, options *ZipOptions) error {
	// Validate inputs
	if len(sourcePaths) == 0 || outputPath == "" {
		return fmt.Errorf("source paths and output path cannot be empty")
	}

	// Check if all sources exist
	for _, sourcePath := range sourcePaths {
		if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
			return fmt.Errorf("source does not exist: %s", sourcePath)
		}
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

	// Process each source
	for _, sourcePath := range sourcePaths {
		info, err := os.Stat(sourcePath)
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", sourcePath, err)
		}

		if info.IsDir() {
			// Handle directory
			err = walkAndAddDirectory(zipWriter, sourcePath, options)
		} else {
			// Handle file
			err = addSingleFileToZip(zipWriter, sourcePath, options)
		}

		if err != nil {
			return fmt.Errorf("failed to add %s to ZIP: %w", sourcePath, err)
		}
	}

	return nil
}

// walkAndAddDirectory - original directory walking logic
func walkAndAddDirectory(zipWriter *zip.Writer, sourceDir string, options *ZipOptions) error {
	// Walk through the source directory and add files to ZIP
	err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
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
			return addFileContentToZip(zipWriter, path, zipPath, info, options)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to create ZIP archive: %w", err)
	}

	return nil
}

// addSingleFileToZip adds a single file to the ZIP archive
func addSingleFileToZip(zipWriter *zip.Writer, filePath string, options *ZipOptions) error {
	// Get file info
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	// For single files, just use the filename as the ZIP path
	zipPath := filepath.Base(filePath)

	return addFileContentToZip(zipWriter, filePath, zipPath, info, options)
}

// addFileContentToZip - extracted common file adding logic
func addFileContentToZip(zipWriter *zip.Writer, sourcePath, zipPath string, info os.FileInfo, options *ZipOptions) error {
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
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		if runtime.GOOS == "windows" {
			fmt.Printf("Warning: Cannot open file %s: %v\n", sourcePath, err)
			return nil
		}
		return fmt.Errorf("failed to open file %s: %w", sourcePath, err)
	}
	defer sourceFile.Close()

	// Copy file content
	if _, err := io.Copy(zipFile, sourceFile); err != nil {
		return fmt.Errorf("failed to write file content: %w", err)
	}

	return nil
}

// isWindowsSystemFile - original implementation
func isWindowsSystemFile(path string) bool {
	if runtime.GOOS != "windows" {
		return false
	}

	// Convert to lowercase for comparison
	lowerPath := strings.ToLower(path)

	// Skip common Windows system directories and files
	systemPaths := []string{
		"$recycle.bin",
		"system volume information",
		"pagefile.sys",
		"hiberfil.sys",
		"swapfile.sys",
	}

	for _, sysPath := range systemPaths {
		if strings.Contains(lowerPath, sysPath) {
			return true
		}
	}

	return false
}

// Placeholder for your encryption implementation
type EncryptionWriter struct {
	writer io.Writer
}

func (ew *EncryptionWriter) Write(p []byte) (n int, err error) {
	// Your encryption logic here
	return ew.writer.Write(p)
}

func (ew *EncryptionWriter) Close() error {
	// Your cleanup logic here
	return nil
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
		options = NewZipOptions()
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
