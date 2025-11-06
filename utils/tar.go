//go:build !windows
// +build !windows

package utils

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sys/unix"
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

// writeStreamEntry writes a single tar entry whose size is unknown in advance.
// It uses a PAX extended header for compliance.
func writeStreamEntry(tw *tar.Writer, r io.Reader, name string) error {
	// 1. Write PAX extended header indicating streaming mode
	paxHdr := &tar.Header{
		Typeflag: tar.TypeXHeader,
		Name:     fmt.Sprintf("PaxHeader/%s", name),
		Mode:     0600,
		ModTime:  time.Now(),
		Format:   tar.FormatPAX,
		PAXRecords: map[string]string{
			"size":    "0",              // Unknown size placeholder
			"path":    name,             // Target name
			"comment": "streamed input", // Optional
		},
	}
	if err := tw.WriteHeader(paxHdr); err != nil {
		return fmt.Errorf("failed to write PAX header: %w", err)
	}

	// 2. Write the file header (size=0, but allowed since we’re using PAX)
	fileHdr := &tar.Header{
		Name:     name,
		Mode:     0600,
		ModTime:  time.Now(),
		Typeflag: tar.TypeReg,
		Size:     0,
		Format:   tar.FormatPAX,
	}
	if err := tw.WriteHeader(fileHdr); err != nil {
		return fmt.Errorf("failed to write stream header: %w", err)
	}

	// 3. Stream data directly to the tar writer’s underlying stream
	written, err := io.Copy(tw, r)
	if err != nil {
		return fmt.Errorf("failed to stream data: %w", err)
	}

	// 4. Align to 512 bytes
	const blockSize = 512
	if pad := (blockSize - (written % blockSize)) % blockSize; pad > 0 {
		if _, err := tw.Write(make([]byte, pad)); err != nil {
			return fmt.Errorf("failed to pad stream: %w", err)
		}
	}

	return nil
}

// CreateTarball accepts either a string or []string (same as your original) and
// now handles unix special files (block/char devices, fifos, sockets) when creating the tar.
func CreateTarball(sources interface{}, outputPath string, options *TarOptions) error {
	if outputPath == "" {
		return fmt.Errorf("output path cannot be empty")
	}

	// Normalize to slice
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

	// Verify each source exists (use Lstat so we don't follow symlinks here)
	for _, f := range fileList {
		if _, err := os.Lstat(f); os.IsNotExist(err) {
			return fmt.Errorf("source path does not exist: %s", f)
		}
	}

	if options == nil {
		options = NewTarOptions()
	}

	// Prepare output
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

	// Encryption
	if options.Encrypt {
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
		// If CompressionLevel==0, zstd uses default; keep user's semantics
		zw, err := zstd.NewWriter(writer, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(options.CompressionLevel)))
		if err != nil {
			return fmt.Errorf("failed to create zstd writer: %w", err)
		}
		defer zw.Close()
		writer = zw
	}

	// Tar writer
	tw := tar.NewWriter(writer)
	defer tw.Close()

	// Track used paths to avoid collisions
	usedNames := make(map[string]struct{})

	for _, source := range fileList {
		source = filepath.Clean(source)

		info, err := os.Lstat(source)
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", source, err)
		}

		// Handle stdin or named pipe input
		if source == "-" || (info != nil && info.Mode()&os.ModeNamedPipe != 0) {
			filename := os.Getenv("TAR_FILENAME")
			if filename == "" {
				filename = "stdin"
			}

			var reader io.Reader
			if source == "-" {
				reader = os.Stdin
			} else {
				f, err := os.Open(source)
				if err != nil {
					return fmt.Errorf("failed to open FIFO %s: %w", source, err)
				}
				defer f.Close()
				reader = f
			}

			if err := writeStreamEntry(tw, reader, filename); err != nil {
				return err
			}

			continue
		}

		if info.IsDir() {
			baseDir := filepath.Base(source)
			err = filepath.Walk(source, func(path string, fi os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				var relPath string
				if options.StripTopLevelDir {
					relPath, err = filepath.Rel(source, path)
				} else {
					relPath, err = filepath.Rel(filepath.Dir(source), path)
				}
				if err != nil {
					return fmt.Errorf("failed to get relative path: %w", err)
				}

				if relPath == "." {
					return nil // skip root entry
				}

				// Collision prevention
				tarPath := filepath.ToSlash(relPath)
				if options.StripTopLevelDir && len(fileList) > 1 {
					if _, exists := usedNames[tarPath]; exists {
						// prefix with original baseDir to avoid collision
						tarPath = filepath.ToSlash(filepath.Join(baseDir, relPath))
					}
				}
				usedNames[tarPath] = struct{}{}

				// readlink for symlink target if symlink
				linkTarget := ""
				if fi.Mode()&os.ModeSymlink != 0 {
					linkTarget, err = os.Readlink(path)
					if err != nil {
						return fmt.Errorf("failed to read symlink target for %s: %w", path, err)
					}
				}

				hdr, err := tar.FileInfoHeader(fi, linkTarget)
				if err != nil {
					return fmt.Errorf("failed to create header for %s: %w", path, err)
				}
				hdr.Name = tarPath

				// Populate device major/minor and typeflag for special files
				if st, ok := fi.Sys().(*syscall.Stat_t); ok {
					// Only set dev fields for device nodes
					rdev := uint64(st.Rdev)
					// Major/minor helpers from unix package
					hdr.Devmajor = int64(unix.Major(rdev))
					hdr.Devminor = int64(unix.Minor(rdev))
				}

				// Adjust Typeflag for FIFOs, sockets, devices (tar.FileInfoHeader may set for some)
				switch fi.Mode() & os.ModeType {
				case os.ModeNamedPipe:
					hdr.Typeflag = tar.TypeFifo
				case os.ModeSocket:
					// no official tar.Type for sockets in Go stdlib; use 's' (GNU extension)
					hdr.Typeflag = byte('s')
				case os.ModeDevice:
					if fi.Mode()&os.ModeCharDevice != 0 {
						hdr.Typeflag = tar.TypeChar
					} else {
						hdr.Typeflag = tar.TypeBlock
					}
				}

				if err := tw.WriteHeader(hdr); err != nil {
					return fmt.Errorf("failed to write header: %w", err)
				}

				// For regular files, copy contents. For others (symlink, fifo, device, socket) do NOT copy content.
				if fi.Mode().IsRegular() {
					f, err := os.Open(path)
					if err != nil {
						return fmt.Errorf("failed to open file %s: %w", path, err)
					}
					defer f.Close()
					if _, err := io.Copy(tw, f); err != nil {
						return fmt.Errorf("failed to copy file %s: %w", path, err)
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
		} else {
			// Single file (or special file)
			name := filepath.Base(source)
			if _, exists := usedNames[name]; exists {
				name = filepath.Base(filepath.Dir(source)) + "_" + name
			}
			usedNames[name] = struct{}{}

			// Use Lstat info for source
			linkTarget := ""
			if info.Mode()&os.ModeSymlink != 0 {
				linkTarget, err = os.Readlink(source)
				if err != nil {
					return fmt.Errorf("failed to read symlink target for %s: %w", source, err)
				}
			}

			hdr, err := tar.FileInfoHeader(info, linkTarget)
			if err != nil {
				return fmt.Errorf("failed to create header for %s: %w", source, err)
			}
			hdr.Name = name

			// device major/minor
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				rdev := uint64(st.Rdev)
				hdr.Devmajor = int64(unix.Major(rdev))
				hdr.Devminor = int64(unix.Minor(rdev))
			}

			// adjust typeflag for special files
			switch info.Mode() & os.ModeType {
			case os.ModeNamedPipe:
				hdr.Typeflag = tar.TypeFifo
			case os.ModeSocket:
				hdr.Typeflag = byte('s')
			case os.ModeDevice:
				if info.Mode()&os.ModeCharDevice != 0 {
					hdr.Typeflag = tar.TypeChar
				} else {
					hdr.Typeflag = tar.TypeBlock
				}
			}

			if err := tw.WriteHeader(hdr); err != nil {
				return fmt.Errorf("failed to write header: %w", err)
			}

			if info.Mode().IsRegular() {
				f, err := os.Open(source)
				if err != nil {
					return fmt.Errorf("failed to open file %s: %w", source, err)
				}
				defer f.Close()
				if _, err := io.Copy(tw, f); err != nil {
					return fmt.Errorf("failed to copy file %s: %w", source, err)
				}
			}
		}
	}

	return nil
}

// ExtractTarball extracts a tarball with optional decompression and decryption.
// It now handles FIFOs and device nodes (if running as root). Sockets are skipped.
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
	if options != nil && options.Encrypt {
		if options.Password == "" {
			return fmt.Errorf("password is required for decryption")
		}
		var decryptedReader io.Reader
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
	if options != nil && options.UseCompression {
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

		// Prevent path traversal: clean and join
		targetPath := filepath.Join(extractDir, filepath.Clean(header.Name))

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}

		case tar.TypeSymlink:
			// Ensure parent exists
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directories for symlink %s: %w", targetPath, err)
			}
			if err := os.Symlink(header.Linkname, targetPath); err != nil {
				return fmt.Errorf("failed to create symlink %s -> %s: %w", targetPath, header.Linkname, err)
			}

		case tar.TypeFifo:
			// create parent
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directories for fifo %s: %w", targetPath, err)
			}
			// create FIFO
			if err := unix.Mkfifo(targetPath, uint32(header.Mode)); err != nil {
				return fmt.Errorf("failed to create fifo %s: %w", targetPath, err)
			}

		case tar.TypeChar, tar.TypeBlock:
			// device nodes — need root to create
			if os.Geteuid() != 0 {
				fmt.Fprintf(os.Stderr, "[WARN] skipping device %s (need root to create device nodes)\n", targetPath)
				// consume data if any (there shouldn't be)
				// no data copy for devices
				continue
			}
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directories for device %s: %w", targetPath, err)
			}
			var devType uint32
			if header.Typeflag == tar.TypeChar {
				devType = unix.S_IFCHR
			} else {
				devType = unix.S_IFBLK
			}
			mode := uint32(header.Mode) | devType
			dev := int(unix.Mkdev(uint32(header.Devmajor), uint32(header.Devminor)))
			if err := unix.Mknod(targetPath, mode, dev); err != nil {
				return fmt.Errorf("failed to mknod device %s: %w", targetPath, err)
			}

		case byte('s'): // socket recorded (GNU extension) — cannot recreate socket; skip
			fmt.Fprintf(os.Stderr, "[INFO] skipping socket %s (sockets are transient and cannot be restored)\n", targetPath)
			continue

		case tar.TypeReg:
			// Regular file
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directories for %s: %w", targetPath, err)
			}
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to write file content: %w", err)
			}
			outFile.Close()

		default:
			// fallback: try to handle as file
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directories for %s: %w", targetPath, err)
			}
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create fallback file %s: %w", targetPath, err)
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to write fallback file content: %w", err)
			}
			outFile.Close()
		}

		// after extraction set mode/time where applicable (symlinks don't take Chmod)
		switch header.Typeflag {
		case tar.TypeDir, tar.TypeReg:
			if err := os.Chmod(targetPath, os.FileMode(header.Mode)); err != nil && header.Typeflag != tar.TypeSymlink {
				// ignore chmod errors on some filesystems or under non-root; warn
				fmt.Fprintf(os.Stderr, "[WARN] failed to chmod %s: %v\n", targetPath, err)
			}
		}
	}

	return nil
}
