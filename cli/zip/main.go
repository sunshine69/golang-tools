package main

import (
	"flag"
	"fmt"
	"os"

	u "github.com/sunshine69/golang-tools/utils"
)

func main() {
	// Define flags
	decomp := flag.Bool("x", false, "Extract mode")
	comp := flag.Bool("c", true, "Compress mode")
	level := flag.Int("l", 6, "Compression level")
	pass := flag.String("p", "", "Zip password. Set to enable encryption")
	output := flag.String("o", "", "Output file (for compress) or directory (for decompress)")
	input := flag.String("i", "", "Input file or directory to compress, or zip file to decompress")
	flag.Parse()

	if *decomp {
		*comp = false
	}
	options := u.NewZipOptions().WithCompressionLevel(*level)
	if *pass != "" {
		options.WithEncrypt(true).WithPassword(*pass)
	}

	if *comp {
		if err := u.CreateZipArchive(*input, *output, options); err != nil {
			fmt.Fprintf(os.Stderr, "Error compressing: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully created zip: %s\n", *output)
	} else {
		if err := u.ExtractZipArchive(*input, *output, options); err != nil {
			fmt.Fprintf(os.Stderr, "Error decompressing: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully extracted to: %s\n", *output)
	}
}
