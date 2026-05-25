package main

import (
	"flag"
	"fmt"
	"os"

	u "github.com/sunshine69/golang-tools/utils"
)

func main() {
	// Define flags
	decomp := flag.String("x", "", "Extract mode. Extract file")
	comp := flag.String("c", "", "Compress mode. Create zip file")
	level := flag.Int("l", 6, "Compression level")
	pass := flag.String("p", "", "Zip password. Set to enable encryption")
	output := flag.String("o", "", "Output file (for compress) or directory (for decompress)")
	input := flag.String("i", "", "Input file or directory to compress")
	flag.Parse()

	options := u.NewZipOptions().WithCompressionLevel(*level)
	if *pass != "" {
		options.WithEncrypt(true).WithPassword(*pass)
	}
	if *comp != "" && *decomp != "" {
		panic("[ERROR] conflicting options, can not create and extract at the same time\n")
	}
	if *comp != "" {
		if err := u.CreateZipArchive(*input, *comp, options); err != nil {
			fmt.Fprintf(os.Stderr, "Error compressing: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully created zip: %s\n", *comp)
	} else {
		if *decomp == "" {
			panic("[ERROR] input file required\n")
		}
		if err := u.ExtractZipArchive(*decomp, *output, options); err != nil {
			fmt.Fprintf(os.Stderr, "Error decompressing: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully extracted to: %s\n", *output)
	}
}
