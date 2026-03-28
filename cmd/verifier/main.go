package main

import (
	"fmt"
	"log"
	"os"

	"github.com/zkmopro/go-zkid-verifier/verifier"
)

func main() {
	baseDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("could not get working directory: %v", err)
	}

	fmt.Printf("=== RS256 ZK Verifier (Go + Rust/Spartan2 FFI) ===\n")
	fmt.Printf("Reading artifacts from: %s/keys/\n\n", baseDir)

	valid, err := verifier.Verify(baseDir)
	if err != nil {
		log.Fatalf("Verify failed: %v", err)
	}
	fmt.Printf("Proof valid: %v\n", valid)
}
