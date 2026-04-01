package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/zkmopro/go-zkid-verifier/challenge"
	"github.com/zkmopro/go-zkid-verifier/store"
)

func main() {
	addr := ":8080"
	if port := os.Getenv("PORT"); port != "" {
		addr = ":" + port
	}

	dbPath := "./zkid.db"
	if p := os.Getenv("DB_PATH"); p != "" {
		dbPath = p
	}

	s, err := store.NewSQLiteStore(dbPath, challenge.DefaultTTL)
	if err != nil {
		log.Fatalf("init store: %v", err)
	}
	defer s.Close()

	handler := challenge.NewHandler(s)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	fmt.Printf("=== zkID Challenge Server ===\n")
	fmt.Printf("Listening on %s\n", addr)
	fmt.Printf("Database: %s\n", dbPath)
	fmt.Printf("Endpoints:\n")
	fmt.Printf("  POST /challenge              - Generate a new challenge\n")
	fmt.Printf("  GET  /challenge/{id}         - Retrieve a challenge\n")
	fmt.Printf("  POST /verify                 - Verify proof against challenge\n")
	fmt.Printf("  GET  /users/{nullifier}/status - Query verification status\n\n")

	if err := http.ListenAndServe(addr, corsMiddleware(logMiddleware(mux))); err != nil {
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

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
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
