package utils

import (
	"fmt"
	"os"
	"runtime"
	"testing"
)

func TestZip(t *testing.T) {
	options := ZipOptions{
		UseCompression:   true,
		CompressionLevel: 6, // Good balance of speed/compression
		Encrypt:          false,
		Password:         "your-secure-password",
	}

	// Windows-friendly paths
	sourceDir := "C:\\Users\\YourName\\Documents"
	outputPath := "backup.zip"

	if runtime.GOOS != "windows" {
		sourceDir = "."
	}
	os.Remove("backup.zip")
	os.RemoveAll("extracted")
	err := CreateZipArchive(sourceDir, outputPath, &options)
	if err != nil {
		fmt.Printf("Error creating ZIP archive: %v\n", err)
		return
	}

	fmt.Println("ZIP archive created successfully!")

	// Extract example
	err = ExtractZipArchive(outputPath, "extracted", &options)
	if err != nil {
		fmt.Printf("Error extracting ZIP archive: %v\n", err)
		return
	}

	fmt.Println("ZIP archive extracted successfully!")
}

// Example usage
func TestTar(t *testing.T) {
	options := TarOptions{
		UseCompression:   true,
		Encrypt:          false,
		Password:         "your-secure-password",
		CompressionLevel: 5,
	}
	os.RemoveAll("output.tar.zst")
	os.RemoveAll("extracted")
	err := CreateTarball("/home/USERNAME/tmp", "output.tar.zst", options)
	if err != nil {
		fmt.Printf("Error creating tarball: %v\n", err)
		return
	}

	fmt.Println("Tarball created successfully!")
	os.MkdirAll("extracted", 0o755)
	CheckErr(ExtractTarball("output.tar.zst", "extracted", options), "")
}
