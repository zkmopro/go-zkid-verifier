package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

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

	if err := http.ListenAndServe(addr, logMiddleware(mux)); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, sw.status, time.Since(start))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
