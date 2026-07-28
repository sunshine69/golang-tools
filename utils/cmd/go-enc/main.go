package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	u "github.com/sunshine69/golang-tools/utils"
)

// This cli is used to encrypt the .htaccess used by the app `devops-app`.

func main() {
	filePath := flag.String("i", "-", "File path to encrypt the file.")
	key := flag.String("k", os.Getenv("SYSTEM_ENCRYPTION_KEY"), "Encryption key. Can set from env var SYSTEM_ENCRYPTION_KEY")
	outfile := flag.String("o", "-", "Output file. If not set it will override the input file")
	ops := flag.String("ops", "enc", "Operations. Support enc|dec for encrypt or decrypt. Default enc")
	flag.Parse()

	var dataIn []byte
	if *filePath == "-" {
		fmt.Println("[INFO] Reading from stdin")
		dataIn = u.Must(io.ReadAll(os.Stdin))
	} else {
		fmt.Printf("Input file '%s'\n", *filePath)
		dataIn = u.Must(os.ReadFile(*filePath))
	}
	dataOut := ""
	switch *ops {
	case "enc":
		dataOut = u.Must(u.Encrypt(string(dataIn), *key, nil))
	case "dec":
		dataOut = u.Must(u.Decrypt(string(dataIn), *key, nil))
	}
	if *outfile == "-" {
		fmt.Println(dataOut)
	} else {
		if *outfile == "" {
			fmt.Println("[WARN] Output file not set, will override input file")
			*outfile = *filePath
		}
		if err := os.WriteFile(*outfile, []byte(dataOut), 0644); err != nil {
			panic("[ERROR] write file " + err.Error())
		}
	}
}
