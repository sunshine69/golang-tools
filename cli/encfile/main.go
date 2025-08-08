package main

import (
	"fmt"
	u "github.com/sunshine69/golang-tools/utils"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: encfile -e|-d -i <input_file> -o <output_file> -p <password>")
		fmt.Println("  -e: encrypt")
		fmt.Println("  -d: decrypt")
		fmt.Println("  -i: input file path")
		fmt.Println("  -o: output file path")
		fmt.Println("  -p: password")
		os.Exit(1)
	}

	var operation string
	var inputFile string
	var outputFile string
	var password string

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-e":
			operation = "encrypt"
		case "-d":
			operation = "decrypt"
		case "-i":
			if i+1 < len(os.Args) {
				inputFile = os.Args[i+1]
				i++
			}
		case "-o":
			if i+1 < len(os.Args) {
				outputFile = os.Args[i+1]
				i++
			}
		case "-p":
			if i+1 < len(os.Args) {
				password = os.Args[i+1]
				i++
			}
		}
	}

	if operation == "" || inputFile == "" || outputFile == "" || password == "" {
		fmt.Println("Error: Missing required arguments")
		fmt.Println("Usage: encfile -e|-d -i <input_file> -o <output_file> -p <password>")
		os.Exit(1)
	}

	if operation != "encrypt" && operation != "decrypt" {
		fmt.Println("Error: Operation must be -e (encrypt) or -d (decrypt)")
		os.Exit(1)
	}

	if operation == "encrypt" {
		u.EncryptFile(inputFile, outputFile, password)
	} else {
		u.DecryptFile(inputFile, outputFile, password)
	}
}
