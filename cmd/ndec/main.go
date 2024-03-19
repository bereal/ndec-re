package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"log"
	"os"

	"github.com/bereal/ndec-re/pkg/ndec"
)

func main() {
	var (
		password1 string
		password2 string
		ivS       string
		input     string
		output    string
	)
	flag.StringVar(&password1, "p1", "", "")
	flag.StringVar(&password2, "p2", "", "")
	flag.StringVar(&ivS, "iv", "", "")
	flag.StringVar(&input, "i", "", "")
	flag.StringVar(&output, "o", "", "")

	flag.Parse()
	cmd := flag.Arg(0)

	if cmd != "encrypt" && cmd != "decrypt" {
		log.Fatal("Command must be either encrypt or decrypt")
	}

	if password1 == "" || password2 == "" {
		log.Fatal("Two passwords flag -p1 and -p2 are required")
	}

	if input == "" {
		log.Fatal("Input file -i is required")
	}

	if output == "" {
		log.Fatal("Output file -o is required")
	}

	data, err := os.ReadFile(input)
	if err != nil {
		log.Fatal(err)
	}

	nd := ndec.New([]byte(password1), []byte(password2))

	if cmd == "encrypt" {
		iv := getIV(ivS)
		nd.Encrypt(data, getIV(ivS))
		data = append([]byte{iv}, data...)
	} else {
		data = nd.Decrypt(data)
	}

	f, err := os.Create(output)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		log.Fatal(err)
	}
}

func getIV(s string) byte {
	var iv []byte
	if s == "" {
		iv = []byte{0}
		if _, err := rand.Read(iv); err != nil {
			log.Fatal(err)
		}
	} else {
		var err error
		iv, err = hex.DecodeString(s)
		if err != nil || len(iv) != 1 {
			log.Fatal("IV must be a single hex byte")
		}
	}
	return iv[0]
}
