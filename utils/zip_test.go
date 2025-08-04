package utils

import (
	"fmt"
	"os"
	"runtime"
	"testing"
)

func TestZip(t *testing.T) {
	options := NewZipOptions()
	// Windows-friendly paths
	sourceDir := `..\gitlab`
	outputPath := "backup.zip"

	if runtime.GOOS != "windows" {
		sourceDir = "."
	}
	os.Remove("backup.zip")
	os.RemoveAll("extracted")
	err := CreateZipArchive(sourceDir, outputPath, options)
	if err != nil {
		fmt.Printf("Error creating ZIP archive: %v\n", err)
		return
	}

	fmt.Println("ZIP archive created successfully!")

	// Extract example
	os.MkdirAll("extracted", 0o755)
	err = ExtractZipArchive(outputPath, "extracted", options)
	if err != nil {
		fmt.Printf("Error extracting ZIP archive: %v\n", err)
		return
	}

	fmt.Println("ZIP archive extracted successfully!")
}

// Example usage
func TestTar(t *testing.T) {
	os.RemoveAll("output.tar.zst")
	os.RemoveAll("extracted")
	err := CreateTarball("../gitlab", "output.tar.zst", NewTarOptions().WithCompressionLevel(3))
	if err != nil {
		fmt.Printf("Error creating tarball: %v\n", err)
		return
	}

	fmt.Println("Tarball created successfully!")
	os.MkdirAll("extracted", 0o755)
	CheckErr(ExtractTarball("output.tar.zst", "extracted", NewTarOptions()), "")
}
