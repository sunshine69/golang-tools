package utils

import (
	"fmt"
	"os"
	"testing"
)

func TestZip(t *testing.T) {
	options := NewZipOptions().WithEncrypt(true).WithPassword(`1qa2ws`)
	// Windows-friendly paths
	sourceDir := `../gitlab`
	outputPath := "backup.zip"

	os.Remove("backup.zip")
	os.RemoveAll("extracted")
	err := CreateZipArchive(sourceDir, outputPath, options)
	if err != nil {
		fmt.Printf("Error creating ZIP archive: %v\n", err)
		return
	}

	fmt.Println("ZIP archive created successfully!")

	// Extract example
	// os.MkdirAll("extracted", 0o755)
	err = ExtractZipArchive(outputPath, "extracted", options)
	if err != nil {
		fmt.Printf("Error extracting ZIP archive from previous cmd: %v\n", err)
		return
	}

	fmt.Println("ZIP archive extracted successfully!")

	err = ExtractZipArchive("sonar-scanner-cli-8.0.1.6346-linux-x64.zip", "extracted", NewZipOptions())
	// err = ExtractZipArchive("t.zip", "extracted", NewZipOptions())
	if err != nil {
		fmt.Printf("Extract from external zip - Error extracting ZIP archive: %v\n", err)
		return
	}

	fmt.Println("External ZIP archive extracted successfully!")
}

// Example usage
func TestTar(t *testing.T) {
	os.RemoveAll("output.tar.zst")
	os.RemoveAll("extracted")
	to := NewTarOptions().WithCompressionLevel(3).WithEncrypt(true).WithPassword(`1qa2ws`)
	println("Create tar ball with encryption")
	err := CreateTarball(`../gitlab`, "output.tar.zst", to)
	if err != nil {
		fmt.Printf("Error creating tarball: %v\n", err)
		return
	}

	fmt.Println("Tarball created successfully!")
	os.MkdirAll("extracted", 0o755)
	CheckErr(ExtractTarball("output.tar.zst", "extracted", to), "")
	fmt.Println("Tarball with encryption extracted successfully!")

	os.RemoveAll("output.tar.zst")

	for _, compFmt := range []CompressionFormat{CompressionGzip, CompressionXz, CompressionZstd} {
		println("Create tar ball with no encryption")
		to = NewTarOptions().WithCompressionLevel(3).WithFormat(compFmt)
		err = CreateTarball(`../gitlab`, "output.tar.zst", to)
		if err != nil {
			fmt.Printf("Error creating tarball: %v\n", err)
			return
		}
		// Note busybox tar will fail. On alpine install gnutar apk add --no-cache tar zstd
		Must(RunSystemCommandV2("tar xf output.tar.zst -C extracted", true))
	}

	fileMap := map[string]string{"test.tgz": "czf", "test.tbz": "cjf", "test.tar.xz": "cJf"}
	for k, v := range fileMap {
		println("Test create and extracting file " + k)
		Must(RunSystemCommandV2("tar "+v+" "+k+" ../gitlab", true))
		if err := ExtractTarball(k, "extracted", nil); err != nil {
			fmt.Printf("Error extrating external tarball %s: %v\n", k, err)
			return
		}
	}

}

func TestZipComplex(t *testing.T) {
	RunSystemCommandV2("rm -f *.zip; rm -rf custom_extract; rm -rf extracted", true)
	// Example 1: Single file
	// Original usage - directory
	err := CreateZipArchive("../gitlab", "directory.zip", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	// New usage - single file
	err = CreateZipArchive("dircopy-linux.go", "single_file.zip", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	// New usage - multiple files/directories
	sources := []string{"dircopy-linux.go", "dircopy-windows.go", "../gitlab"}
	options := &ZipOptions{
		UseCompression: true,
		Encrypt:        false,
	}
	err = CreateZipArchive(sources, "multiple_sources.zip", options)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	CheckErr(ExtractZipArchive("multiple_sources.zip", "multiple-sources", options), "")
	// With encryption (using your implementation)
	encryptedOptions := &ZipOptions{
		UseCompression: true,
		Encrypt:        true,
		Password:       "mypassword",
	}
	err = CreateZipArchive("../gitlab", "encrypted.zip", encryptedOptions)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	CheckErr(ExtractZipArchive("encrypted.zip", "extracted_encrypted", encryptedOptions), "")
}

func TestCpio(t *testing.T) {
	opt := NewCompEncOptions().WithEncrypt(true).WithPassword("123").WithCompression(true).WithOverwriteExisting(true).WithEncryptMode(EncryptModeCTR)
	CheckErr(CreateCompEncArchive("go.sum", "/tmp/test-cpio.compenc", opt), "")
	CheckErr(ExtractCompEncArchive("/tmp/test-cpio.compenc", "-", opt), "")
}
