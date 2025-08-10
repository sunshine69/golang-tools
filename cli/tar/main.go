package main

import (
	"flag"
	"fmt"
	"os"

	u "github.com/sunshine69/golang-tools/utils"
)

var (
	compressLevel          *int = flag.Int("l", 5, "Zstd compression level 0-21")
	enableGCM                   = flag.Bool("em", false, "Enable GCM Encryption Mode: Default CTR suitable for streaming data and big file")
	enableStripTopLevelDir      = flag.Bool("strip-dir", false, "Strip top level dir")
	encrypt                bool
	password               = flag.String("p", "", "Password for encryption. If provided encrypt is enabled")
	tarOption              *u.TarOptions
)

func SetTarOpt() {
	encrypt = *password != ""
	tarOption = u.NewTarOptions().WithCompressionLevel(*compressLevel)
	if encrypt {
		tarOption = tarOption.WithEncrypt(true).WithPassword(*password)
		if *enableGCM {
			tarOption = tarOption.WithEncryptMode(u.EncryptModeGCM)
		}
	}
	tarOption = tarOption.WithStripTopLevelDir(*enableStripTopLevelDir)
}

func main() {
	// Create flags
	create := flag.Bool("c", false, "Create archive")
	extract := flag.Bool("x", false, "Extract archive")
	var inputFiles u.ArrayFlags
	flag.Var(&inputFiles, "i", "Input file(s)")
	outputFile := flag.String("o", "", "Output file/dir (for create or extract")

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
	if len(inputFiles) == 0 || *outputFile == "" {
		fmt.Fprintf(os.Stderr, "Input and output file/path required\n")
		os.Exit(1)
	}

	// Call appropriate function based on operation using switch
	SetTarOpt()
	switch operation {
	case "create":
		u.CheckErr(u.CreateTarball(inputFiles, *outputFile, tarOption), "CreateTarball")
	case "extract":
		u.CheckErr(u.ExtractTarball(inputFiles[0], *outputFile, tarOption), "ExtractTarball")
	}
}
