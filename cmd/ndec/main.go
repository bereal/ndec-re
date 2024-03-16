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
		iv        string
		input     string
		output    string
	)
	flag.StringVar(&password1, "p1", "", "")
	flag.StringVar(&password2, "p2", "", "")
	flag.StringVar(&iv, "iv", "", "")
	flag.StringVar(&input, "i", "", "")
	flag.StringVar(&output, "o", "", "")

	flag.Parse()

	if password1 == "" || password2 == "" {
		log.Fatal("Two passwords flag -p1 and -p2 are required")
	}

	if input == "" {
		log.Fatal("Input file -i is required")
	}

	if output == "" {
		log.Fatal("Output file -o is required")
	}

	var ivB []byte
	if iv == "" {
		ivB = []byte{0}
		if _, err := rand.Read(ivB); err != nil {
			log.Fatal(err)
		}
	} else {
		var err error
		ivB, err = hex.DecodeString(iv)
		if err != nil || len(ivB) != 1 {
			log.Fatal("IV must be a single hex byte")
		}
	}

	data, err := os.ReadFile(input)
	if err != nil {
		log.Fatal(err)
	}

	nd := ndec.New([]byte(password1), []byte(password2))
	nd.Encrypt(data, ivB[0])

	f, err := os.Create(output)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if _, err = f.Write(ivB); err != nil {
		log.Fatal(err)
	}

	if _, err = f.Write(data); err != nil {
		log.Fatal(err)
	}
}
