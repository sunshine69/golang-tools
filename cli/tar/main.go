package main

import (
	"flag"
	"fmt"
	"os"

	u "github.com/sunshine69/golang-tools/utils"
)

var compressLevel *int = flag.Int("l", 5, "Zstd compression level 0-21")
var encMode = flag.String("em", "", "Encryption Mode: GCM or CTR. Default CTR if empty")

func main() {
	// Create flags
	create := flag.Bool("c", false, "Create archive")
	extract := flag.Bool("x", false, "Extract archive")
	inputFile := flag.String("i", "", "Input file (for extract) dir for create")
	outputFile := flag.String("o", "", "Output file (for create) or extract dir")
	password := flag.String("p", "", "Password for encryption. If provided encrypt is enabled")

	// Parse flags
	flag.Parse()

	// Validate operation using switch
	var operation string
	switch {
	case *create:
		operation = "create"
	case *extract:
		operation = "extract"
	default:
		fmt.Println("Error: Operation (-c or -x) is required")
		flag.Usage()
		os.Exit(1)
	}

	// Validate directories
	if *inputFile == "" || *outputFile == "" {
		fmt.Fprintf(os.Stderr, "Input and output file/path required\n")
		os.Exit(1)
	}

	// Call appropriate function based on operation using switch

	switch operation {
	case "create":
		createTar(*inputFile, *outputFile, *password != "", *password)
	case "extract":
		extractTar(*inputFile, *outputFile, *password != "", *password)
	}
}

func createTar(inputDir, outputFile string, encrypt bool, password string) {
	fmt.Fprintf(os.Stderr, "Creating tar archive from %s to %s\n", inputDir, outputFile)
	to := u.NewTarOptions().WithCompressionLevel(*compressLevel)
	if encrypt {
		to = to.WithEncrypt(true).WithPassword(password)
		if *encMode == "GCM" {
			to = to.WithEncryptMode(u.EncryptModeGCM)
		}
	}
	u.CheckErr(u.CreateTarball(inputDir, outputFile, to), "")
}

func extractTar(inputFile, extractDir string, encrypt bool, password string) {
	fmt.Fprintf(os.Stderr, "Extracting archive %s to %s\n", inputFile, extractDir)
	to := u.NewTarOptions().WithCompressionLevel(*compressLevel)
	if encrypt {
		to = to.WithEncrypt(true).WithPassword(password)
		if *encMode == "GCM" {
			to = to.WithEncryptMode(u.EncryptModeGCM)
		}
	}
	u.CheckErr(u.ExtractTarball(inputFile, extractDir, to), "")
}
