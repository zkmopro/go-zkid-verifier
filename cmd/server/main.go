package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/zkmopro/go-zkid-verifier/challenge"
)

func main() {
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
	fmt.Printf("  POST /challenge      - Generate a new challenge\n")
	fmt.Printf("  GET  /challenge/{id} - Retrieve a challenge\n")
	fmt.Printf("  POST /verify         - Verify proof against challenge\n\n")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
