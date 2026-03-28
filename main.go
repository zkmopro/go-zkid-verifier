package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/zkmopro/go-zkid-verifier/challenge"
	"github.com/zkmopro/go-zkid-verifier/verifier"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		runServer()
		return
	}

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

func runServer() {
	addr := ":8080"
	if port := os.Getenv("PORT"); port != "" {
		addr = ":" + port
	}

	store := challenge.NewStore(challenge.DefaultTTL)
	handler := challenge.NewHandler(store)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	fmt.Printf("=== zkID Challenge Server ===\n")
	fmt.Printf("Listening on %s\n", addr)
	fmt.Printf("Endpoints:\n")
	fmt.Printf("  POST /challenge    - Generate a new challenge\n")
	fmt.Printf("  GET  /challenge/{id} - Retrieve a challenge\n")
	fmt.Printf("  POST /verify       - Verify proof against challenge\n\n")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
