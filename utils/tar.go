//go:build !windows
// +build !windows

package utils

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	"golang.org/x/sys/unix"
)

// tar works and well tested on linux. Without encryption it is compatible with the tar command

// CompressionFormat selects the compression algorithm
type CompressionFormat int

const (
	CompressionZstd  CompressionFormat = iota // default, existing behaviour
	CompressionGzip                           // .tar.gz / .tgz
	CompressionBzip2                          // .tar.bz2  (read-only; bzip2 stdlib has no writer)
	CompressionXz                             // .tar.xz
	CompressionNone                           // no compression
)

func IsFIFO(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.Mode()&os.ModeNamedPipe != 0, nil
}

// TarOptions contains configuration for the tar creation
type TarOptions struct {
	UseCompression   bool
	Format           CompressionFormat // NEW: which algorithm to use
	Encrypt          bool
	EncryptMode      EncryptMode
	Password         string
	CompressionLevel int // meaning depends on Format: zstd 1-22, gzip 1-9, xz 0-9
	StripTopLevelDir bool
}

func NewTarOptions() *TarOptions {
	return &TarOptions{
		UseCompression:   true,
		Format:           CompressionZstd,
		CompressionLevel: 3,
		Encrypt:          false,
		EncryptMode:      EncryptModeCTR,
		Password:         "",
		StripTopLevelDir: true,
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
func (zo *TarOptions) WithFormat(f CompressionFormat) *TarOptions {
	zo.Format = f
	return zo
}

// detectFormat sniffs the first few bytes of a reader to determine the
// compression format. It returns the format and an io.Reader that still
// contains the sniffed bytes (via io.MultiReader).
func detectFormat(r io.Reader) (CompressionFormat, io.Reader, error) {
	magic := make([]byte, 6)
	n, err := io.ReadFull(r, magic)
	if err != nil && n == 0 {
		return CompressionNone, r, fmt.Errorf("failed to read magic bytes: %w", err)
	}
	magic = magic[:n]

	full := io.MultiReader(bytes.NewReader(magic), r)

	switch {
	case n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		return CompressionGzip, full, nil
	case n >= 3 && magic[0] == 'B' && magic[1] == 'Z' && magic[2] == 'h':
		return CompressionBzip2, full, nil
	case n >= 6 &&
		magic[0] == 0xFD && magic[1] == '7' && magic[2] == 'z' &&
		magic[3] == 'X' && magic[4] == 'Z' && magic[5] == 0x00:
		return CompressionXz, full, nil
	// zstd magic: 0xFD2FB528 little-endian
	case n >= 4 && magic[0] == 0x28 && magic[1] == 0xB5 && magic[2] == 0x2F && magic[3] == 0xFD:
		return CompressionZstd, full, nil
	default:
		return CompressionNone, full, nil
	}
}

// bytesReader wraps a []byte as an io.Reader (avoids importing bytes just for this)
type bytesReader []byte

func (b *bytesReader) Read(p []byte) (int, error) {
	if len(*b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, *b)
	*b = (*b)[n:]
	return n, nil
}

// wrapCompressionWriter wraps w with the requested compression algorithm.
// Returns the new writer and a closer (call close when done writing).
// For CompressionNone or when UseCompression==false it returns w unchanged.
func wrapCompressionWriter(w io.Writer, options *TarOptions) (io.Writer, func() error, error) {
	nop := func() error { return nil }
	if !options.UseCompression || options.Format == CompressionNone {
		return w, nop, nil
	}
	switch options.Format {
	case CompressionZstd:
		level := options.CompressionLevel
		if level == 0 {
			level = 3
		}
		zw, err := zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create zstd writer: %w", err)
		}
		return zw, zw.Close, nil
	case CompressionGzip:
		level := options.CompressionLevel
		if level == 0 {
			level = gzip.DefaultCompression
		}
		gw, err := gzip.NewWriterLevel(w, level)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create gzip writer: %w", err)
		}
		return gw, gw.Close, nil
	case CompressionBzip2:
		// stdlib compress/bzip2 is read-only; reject early with a clear message.
		return nil, nil, fmt.Errorf("bzip2 write is not supported by the Go standard library; use gzip or zstd for creation")
	case CompressionXz:
		level := options.CompressionLevel
		cfg := xz.WriterConfig{}
		if level > 0 {
			cfg.DictCap = xzDictCapForLevel(level)
		}
		xw, err := cfg.NewWriter(w)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create xz writer: %w", err)
		}
		return xw, xw.Close, nil
	default:
		return w, nop, nil
	}
}

// xzDictCapForLevel maps a 1-9 level to an xz dictionary capacity.
// Higher dict = better ratio but more RAM.
func xzDictCapForLevel(level int) int {
	caps := []int{
		1 << 16, // level 1  64 KiB
		1 << 17, // level 2 128 KiB
		1 << 18, // level 3 256 KiB
		1 << 19, // level 4 512 KiB
		1 << 20, // level 5   1 MiB
		1 << 21, // level 6   2 MiB
		1 << 22, // level 7   4 MiB
		1 << 23, // level 8   8 MiB
		1 << 24, // level 9  16 MiB
	}
	if level < 1 {
		level = 1
	}
	if level > 9 {
		level = 9
	}
	return caps[level-1]
}

// wrapDecompressionReader wraps r with a decompression layer based on options.
// If options.Format == CompressionNone and options.UseCompression is true, it
// auto-detects the format from the stream magic bytes.
func wrapDecompressionReader(r io.Reader, options *TarOptions) (io.Reader, func() error, error) {
	nop := func() error { return nil }
	if options == nil || !options.UseCompression {
		return r, nop, nil
	}

	format := options.Format

	// Auto-detect when caller hasn't specified a concrete format.
	// We treat CompressionZstd as "I set a specific format" to preserve
	// backwards-compat; only auto-detect when the caller explicitly passes
	// CompressionNone as the format but UseCompression==true (meaning
	// "decompress but I don't know the format").
	if format == CompressionNone {
		detected, newR, err := detectFormat(r)
		if err != nil {
			return nil, nil, err
		}
		r = newR
		format = detected
	}

	switch format {
	case CompressionZstd:
		zr, err := zstd.NewReader(r)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create zstd reader: %w", err)
		}
		return zr, func() error { zr.Close(); return nil }, nil
	case CompressionGzip:
		gr, err := gzip.NewReader(r)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		return gr, gr.Close, nil
	case CompressionBzip2:
		// bzip2 reader is synchronous and has no Close()
		return bzip2.NewReader(r), nop, nil
	case CompressionXz:
		xr, err := xz.NewReader(r)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create xz reader: %w", err)
		}
		return xr, nop, nil
	default:
		// No recognised compression; pass through raw
		return r, nop, nil
	}
}

// CreateTarball accepts either a string or []string (same as your original) and
// handles unix special files (block/char devices, fifos, sockets) when creating the tar.
// If outputPath is "-" then write to stdout.
func CreateTarball(sources interface{}, outputPath any, options *TarOptions) error {
	if outputPath == "" {
		return fmt.Errorf("output path cannot be empty")
	}

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
	switch v := outputPath.(type) {
	case string:
		switch v {
		case "-":
			outputFile = os.Stdout
		default:
			if ok, _ := IsFIFO(v); ok {
				fifo, err := os.OpenFile(v, os.O_WRONLY, os.ModeNamedPipe)
				if err != nil {
					return fmt.Errorf("error opening FIFO: %w", err)
				}
				outputFile = fifo
			} else {
				outputFile = Must(os.Create(v))
			}
		}
	case io.WriteCloser:
		outputFile = v
	default:
		return fmt.Errorf("output must be a file path or an io.WriteCloser")
	}
	defer outputFile.Close()

	var writer io.Writer = outputFile

	// Encryption (non-standard layer; only for archives produced by this library)
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
				return fmt.Errorf("failed to create encryption writer: %w", err)
			}
			defer ew.Close()
		}
		writer = ew
	}

	// Compression
	compWriter, compClose, err := wrapCompressionWriter(writer, options)
	if err != nil {
		return err
	}
	defer compClose()
	writer = compWriter

	tw := tar.NewWriter(writer)
	defer tw.Close()

	usedNames := make(map[string]struct{})

	for _, source := range fileList {
		source = filepath.Clean(source)

		info, err := os.Lstat(source)
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", source, err)
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
					return nil
				}

				tarPath := filepath.ToSlash(relPath)
				if options.StripTopLevelDir && len(fileList) > 1 {
					if _, exists := usedNames[tarPath]; exists {
						tarPath = filepath.ToSlash(filepath.Join(baseDir, relPath))
					}
				}
				usedNames[tarPath] = struct{}{}

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

				if st, ok := fi.Sys().(*syscall.Stat_t); ok {
					rdev := uint64(st.Rdev)
					hdr.Devmajor = int64(unix.Major(rdev))
					hdr.Devminor = int64(unix.Minor(rdev))
				}

				switch fi.Mode() & os.ModeType {
				case os.ModeNamedPipe:
					hdr.Typeflag = tar.TypeFifo
				case os.ModeSocket:
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
			name := filepath.Base(source)
			if _, exists := usedNames[name]; exists {
				name = filepath.Base(filepath.Dir(source)) + "_" + name
			}
			usedNames[name] = struct{}{}

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

			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				rdev := uint64(st.Rdev)
				hdr.Devmajor = int64(unix.Major(rdev))
				hdr.Devminor = int64(unix.Minor(rdev))
			}

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
// Compression format is auto-detected from magic bytes when options.Format is
// CompressionNone (or options is nil with UseCompression true).
// If tarballPath is "-" then read from stdin.
func ExtractTarball(tarballPath any, extractDir string, options *TarOptions) error {
	var file io.ReadCloser
	var err error
	switch v := tarballPath.(type) {
	case string:
		switch v {
		case "-":
			file = os.Stdin
		default:
			file, err = os.Open(v)
			if err != nil {
				return fmt.Errorf("failed to open tarball: %w", err)
			}
		}
	case io.ReadCloser:
		file = v
	default:
		return fmt.Errorf("tarballPath must be a file path string or io.ReadCloser")
	}
	defer file.Close()

	var reader io.Reader = file

	// Decryption layer (non-standard; only for archives produced by this library)
	if options != nil && options.Encrypt {
		if options.Password == "" {
			return fmt.Errorf("password is required for decryption")
		}
		switch options.EncryptMode {
		case EncryptModeGCM:
			reader, err = CreateDecryptionReader(file, options.Password)
			if err != nil {
				return fmt.Errorf("failed to create decryption reader GCM: %w", err)
			}
		case EncryptModeCTR:
			reader, err = NewStreamDecryptReader(file, options.Password)
			if err != nil {
				return fmt.Errorf("failed to create decryption reader CTR: %w", err)
			}
		}
	}

	// Decompression layer — auto-detects format when Format==CompressionNone
	if options == nil {
		// default: auto-detect compression
		options = &TarOptions{UseCompression: true, Format: CompressionNone}
	}
	decompReader, decompClose, err := wrapDecompressionReader(reader, options)
	if err != nil {
		return err
	}
	defer decompClose()
	reader = decompReader

	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		targetPath := filepath.Join(extractDir, filepath.Clean(header.Name))

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}

		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directories for symlink %s: %w", targetPath, err)
			}
			if err := os.Symlink(header.Linkname, targetPath); err != nil {
				return fmt.Errorf("failed to create symlink %s -> %s: %w", targetPath, header.Linkname, err)
			}

		case tar.TypeFifo:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directories for fifo %s: %w", targetPath, err)
			}
			if err := unix.Mkfifo(targetPath, uint32(header.Mode)); err != nil {
				return fmt.Errorf("failed to create fifo %s: %w", targetPath, err)
			}

		case tar.TypeChar, tar.TypeBlock:
			if os.Geteuid() != 0 {
				fmt.Fprintf(os.Stderr, "[WARN] skipping device %s (need root to create device nodes)\n", targetPath)
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

		case byte('s'):
			fmt.Fprintf(os.Stderr, "[INFO] skipping socket %s (sockets are transient and cannot be restored)\n", targetPath)
			continue

		case tar.TypeReg:
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

		switch header.Typeflag {
		case tar.TypeDir, tar.TypeReg:
			if err := os.Chmod(targetPath, os.FileMode(header.Mode)); err != nil {
				fmt.Fprintf(os.Stderr, "[WARN] failed to chmod %s: %v\n", targetPath, err)
			}
		}
	}

	return nil
}
