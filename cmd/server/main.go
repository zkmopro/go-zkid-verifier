package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/zkmopro/go-zkid-verifier/challenge"
	zkgrpc "github.com/zkmopro/go-zkid-verifier/grpc"
	"github.com/zkmopro/go-zkid-verifier/keymanager"
	pb "github.com/zkmopro/go-zkid-verifier/proto/zkid/v1"
	"github.com/zkmopro/go-zkid-verifier/store"
	"google.golang.org/grpc"
)

func main() {
	httpAddr := ":8080"
	if port := os.Getenv("PORT"); port != "" {
		httpAddr = ":" + port
	}

	grpcAddr := ":9090"
	if port := os.Getenv("GRPC_PORT"); port != "" {
		grpcAddr = ":" + port
	}

	dbPath := "./zkid.db"
	if p := os.Getenv("DB_PATH"); p != "" {
		dbPath = p
	}

	keysDir := "./keys"
	if p := os.Getenv("KEYS_DIR"); p != "" {
		keysDir = p
	}
	keysDir, _ = filepath.Abs(keysDir)

	// Download verifying keys if missing
	log.Printf("Checking verifying keys in %s...", keysDir)
	if err := keymanager.EnsureKeys(keysDir); err != nil {
		log.Printf("WARNING: key download failed: %v", err)
		log.Printf("Link-verify will not work until keys are available.")
	}

	s, err := store.NewSQLiteStore(dbPath, challenge.DefaultTTL)
	if err != nil {
		log.Fatalf("init store: %v", err)
	}
	defer s.Close()

	handler := challenge.NewHandler(s, keysDir)

	// HTTP server
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	fmt.Printf("=== zkID Verifier Server ===\n")
	fmt.Printf("HTTP listening on %s\n", httpAddr)
	fmt.Printf("gRPC listening on %s\n", grpcAddr)
	fmt.Printf("Database: %s\n", dbPath)
	fmt.Printf("Keys directory: %s\n", keysDir)
	fmt.Printf("REST Endpoints:\n")
	fmt.Printf("  POST /challenge              - Generate a new challenge\n")
	fmt.Printf("  GET  /challenge/{id}         - Retrieve a challenge\n")
	fmt.Printf("  POST /verify-tbs             - Verify TBS hash against challenge\n")
	fmt.Printf("  POST /link-verify            - Verify ZK proofs with pk_commit linkage\n")
	fmt.Printf("  GET  /users/{nullifier}/status - Query verification status\n\n")

	// Start gRPC server in a goroutine
	go func() {
		lis, err := net.Listen("tcp", grpcAddr)
		if err != nil {
			log.Fatalf("gRPC listen: %v", err)
		}
		grpcServer := grpc.NewServer()
		pb.RegisterZkIDVerifierServer(grpcServer, zkgrpc.NewServer(s, keysDir))
		log.Printf("gRPC server started on %s", grpcAddr)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("gRPC serve: %v", err)
		}
	}()

	if err := http.ListenAndServe(httpAddr, corsMiddleware(logMiddleware(mux))); err != nil {
		log.Fatalf("HTTP server error: %v", err)
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
