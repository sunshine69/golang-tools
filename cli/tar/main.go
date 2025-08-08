package main

import (
	"flag"
	"fmt"
	"os"

	u "github.com/sunshine69/golang-tools/utils"
)

var compressLevel *int = flag.Int("l", 5, "Zstd compression level 0-21")

func main() {
	// Create flags
	create := flag.Bool("c", false, "Create archive")
	extract := flag.Bool("x", false, "Extract archive")
	inputFile := flag.String("f", "", "Input file (for extract)")
	outputFile := flag.String("o", "", "Output file (for create)")
	inputDir := flag.String("d", ".", "Input directory (for create)")
	extractDir := flag.String("C", ".", "Extract directory (for extract)")
	encrypt := flag.Bool("e", false, "Enable encryption")
	password := flag.String("p", "", "Password for encryption")

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

	// Validate required arguments using switch
	switch operation {
	case "create":
		if *outputFile == "" {
			fmt.Println("Error: Output file (-o) is required for create operation")
			flag.Usage()
			os.Exit(1)
		}
	case "extract":
		if *inputFile == "" {
			fmt.Println("Error: Input file (-f) is required for extract operation")
			flag.Usage()
			os.Exit(1)
		}
	}

	// Validate directories
	switch operation {
	case "create":
		if _, err := os.Stat(*inputDir); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Error: Input directory does not exist: %s\n", *inputDir)
			os.Exit(1)
		}
	case "extract":
		if _, err := os.Stat(*extractDir); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Error: Extract directory does not exist: %s\n", *extractDir)
			os.Exit(1)
		}
	}

	// Display configuration
	// fmt.Fprintf(os.Stderr, "Operation: %s\n", operation)
	// fmt.Fprintf(os.Stderr, "Input Dir: %s\n", *inputDir)
	// fmt.Fprintf(os.Stderr, "Output File: %s\n", *outputFile)
	// fmt.Fprintf(os.Stderr, "Input File: %s\n", *inputFile)
	// fmt.Fprintf(os.Stderr, "Extract Dir: %s\n", *extractDir)
	// fmt.Fprintf(os.Stderr, "Encrypt: %t\n", *encrypt)

	// Call appropriate function based on operation using switch
	switch operation {
	case "create":
		createTar(*inputDir, *outputFile, *encrypt, *password)
	case "extract":
		extractTar(*inputFile, *extractDir, *encrypt, *password)
	}
}

func createTar(inputDir, outputFile string, encrypt bool, password string) {
	fmt.Fprintf(os.Stderr, "Creating tar archive from %s to %s\n", inputDir, outputFile)
	to := u.NewTarOptions().WithCompressionLevel(*compressLevel)
	if encrypt {
		to = to.WithEncrypt(true).WithPassword(password)
	}
	u.CheckErr(u.CreateTarball(inputDir, outputFile, to), "")
}

func extractTar(inputFile, extractDir string, encrypt bool, password string) {
	fmt.Fprintf(os.Stderr, "Extracting archive %s to %s\n", inputFile, extractDir)
	to := u.NewTarOptions().WithCompressionLevel(*compressLevel)
	if encrypt {
		to = to.WithEncrypt(true).WithPassword(password)
	}
	u.CheckErr(u.ExtractTarball(inputFile, extractDir, to), "")
}
