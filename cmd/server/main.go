package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zkmopro/go-zkid-verifier/challenge"
	zkgrpc "github.com/zkmopro/go-zkid-verifier/grpc"
	"github.com/zkmopro/go-zkid-verifier/httpapi"
	"github.com/zkmopro/go-zkid-verifier/keymanager"
	"github.com/zkmopro/go-zkid-verifier/linkverify"
	pb "github.com/zkmopro/go-zkid-verifier/proto/zkid/v1"
	"github.com/zkmopro/go-zkid-verifier/smtroot"
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

	corsOrigin := os.Getenv("CORS_ORIGIN")
	if corsOrigin == "" {
		corsOrigin = "*"
	}

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	provider, err := buildSmtRootProvider(ctx)
	if err != nil {
		log.Fatalf("smt root provider: %v", err)
	}
	verifier := &linkverify.Verifier{
		KeysDir: keysDir,
		SmtRoot: provider,
		Logger:  smtroot.DefaultLogger{},
	}
	if provider != nil {
		provider.Start(ctx)
		defer provider.Stop()
	}

	service := linkverify.NewService(verifier, s)

	// Bind gRPC listener in main (fail fast before any server starts)
	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Fatalf("gRPC listen on %s: %v", grpcAddr, err)
	}

	mux := httpapi.NewRouter(service, s, provider)

	fmt.Printf("=== zkID Verifier Server ===\n")
	fmt.Printf("HTTP listening on %s\n", httpAddr)
	fmt.Printf("gRPC listening on %s\n", grpcAddr)
	fmt.Printf("Database: %s\n", dbPath)
	fmt.Printf("Keys directory: %s\n", keysDir)
	fmt.Printf("REST Endpoints:\n")
	fmt.Printf("  POST /challenge              - Generate a new challenge\n")
	fmt.Printf("  GET  /challenge/{id}         - Retrieve a challenge\n")
	fmt.Printf("  POST /link-verify            - Verify ZK proofs with pk_commit linkage\n")
	fmt.Printf("  GET  /smt-root/status        - Query trusted SMT root cache\n\n")

	// Start gRPC server in a goroutine (listener already bound)
	go func() {
		grpcServer := grpc.NewServer(
			grpc.MaxRecvMsgSize(2 * 1024 * 1024), // 2MB, match HTTP limit
		)
		pb.RegisterZkIDVerifierServer(grpcServer, zkgrpc.NewServer(service, s))
		log.Printf("gRPC server started on %s", grpcAddr)
		if err := grpcServer.Serve(grpcLis); err != nil {
			log.Printf("gRPC serve error: %v", err)
		}
	}()

	if err := http.ListenAndServe(httpAddr, corsMiddleware(corsOrigin, logMiddleware(mux))); err != nil {
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

func corsMiddleware(origin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
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

// buildSmtRootProvider returns (nil, nil) when SMT_ROOT_ENFORCE=disabled.
// Otherwise it requires at least one source to succeed at boot (fail-closed).
func buildSmtRootProvider(ctx context.Context) (*smtroot.Provider, error) {
	mode := strings.ToLower(os.Getenv("SMT_ROOT_ENFORCE"))
	if mode == "disabled" {
		log.Printf("SMT_ROOT_ENFORCE=disabled — link-verify will NOT check the SMT root (dev only)")
		return nil, nil
	}

	timeout := envDuration("SMT_ROOT_FETCH_TIMEOUT", 5*time.Second)
	refresh := envDuration("SMT_ROOT_REFRESH_INTERVAL", 10*time.Minute)

	onchain := smtroot.NewOnchainSource(
		os.Getenv("SMT_ROOT_RPC_URL"),
		os.Getenv("SMT_ROOT_CONTRACT"),
		timeout,
	)
	github := smtroot.NewGitHubReleaseSource(
		os.Getenv("SMT_ROOT_GITHUB_REPO"),
		os.Getenv("SMT_ROOT_GITHUB_TAG"),
		timeout,
	)

	p := smtroot.NewProvider(smtroot.Config{
		Primary:         onchain,
		Fallback:        github,
		RefreshInterval: refresh,
		FetchTimeout:    timeout,
	})

	startupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := p.FetchNow(startupCtx, "startup"); err != nil {
		return nil, fmt.Errorf("startup fetch (set SMT_ROOT_ENFORCE=disabled to skip): %w", err)
	}
	return p, nil
}

func envDuration(name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Printf("invalid %s=%q: %v; using default %s", name, v, err, def)
		return def
	}
	if d <= 0 {
		log.Printf("%s=%q must be positive; using default %s", name, v, def)
		return def
	}
	return d
}
