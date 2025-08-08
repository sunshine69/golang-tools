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
	to := NewTarOptions().WithCompressionLevel(3).WithEncrypt(true).WithPassword(`1qa2ws`)
	err := CreateTarball(`../gitlab`, "output.tar.zst", to)
	if err != nil {
		fmt.Printf("Error creating tarball: %v\n", err)
		return
	}

	fmt.Println("Tarball created successfully!")
	os.MkdirAll("extracted", 0o755)
	CheckErr(ExtractTarball("output.tar.zst", "extracted", to), "")
	fmt.Println("Tarball extracted successfully!")
}
