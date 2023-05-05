package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "This script takes exactly 2 arguments (%d passed)\n\nUsage: %s <ssid> <password>\n", len(os.Args)-1, os.Args[0])
		os.Exit(1)
	}

	ssid := os.Args[1]
	password := os.Args[2]

	key := pbkdf2.Key([]byte(password), []byte(ssid), 4096, 32, sha1.New)

	fmt.Println(hex.EncodeToString(key))
}
