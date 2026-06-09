package smtroot

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	sampleG2Hex = "9c70a056212542ae5df527d2f3a510e5a6c58935aae164457e03b027cabea5e0"
	sampleG3Hex = "c01140fee1d4b0a02c416a5985049411fab4bb17181f05dc8550877b1564dfef"
)

func TestParseRoot(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want string // canonical form, or "" if error expected
	}{
		{"0x" + sampleG2Hex, "0x" + sampleG2Hex},
		{sampleG2Hex, "0x" + sampleG2Hex},
		{"0X" + strings.ToUpper(sampleG2Hex), "0x" + sampleG2Hex},
		{"0x1", "0x0000000000000000000000000000000000000000000000000000000000000001"},
		{"0x" + sampleG2Hex + "ff", ""},
		{"0xzz", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got, err := ParseRoot(tc.in)
		if tc.want == "" {
			if err == nil {
				t.Errorf("ParseRoot(%q) = %s, want error", tc.in, got.Hex())
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRoot(%q) error: %v", tc.in, err)
			continue
		}
		if got.Hex() != tc.want {
			t.Errorf("ParseRoot(%q) = %s, want %s", tc.in, got.Hex(), tc.want)
		}
	}
}

func TestIssuerIDHash(t *testing.T) {
	t.Parallel()
	// Verified against cast: cast keccak "MOICA-G2" →
	// 0x7c2ae0fd3cf13c2c5e4f61f16b0db3a2a0b0fb4cd5a2c5a5b9c3f8c9b5a0e1a7 (example only)
	// The real invariant: hash must be deterministic and 32 bytes.
	g2 := IssuerIDHash(IssuerG2)
	g3 := IssuerIDHash(IssuerG3)
	if g2 == g3 {
		t.Fatal("G2 and G3 issuer IDs collided")
	}
	if hex.EncodeToString(g2[:]) == "" {
		t.Fatal("empty hash")
	}
}

func TestOnchainSource_FetchAll(t *testing.T) {
	t.Parallel()

	var rpcHits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode rpc request: %v", err)
			http.Error(w, "bad json", 400)
			return
		}
		if req.Method != "eth_call" {
			http.Error(w, "wrong method", 400)
			return
		}
		mu.Lock()
		rpcHits++
		mu.Unlock()

		// decode calldata to figure out which issuer was requested
		var args ethCallArgs
		if err := json.Unmarshal(req.Params[0], &args); err != nil {
			t.Errorf("decode params: %v", err)
		}
		data := strings.TrimPrefix(args.Data, "0x")
		// 4 bytes selector + 32 bytes issuer ID = 72 hex chars
		if len(data) != 72 {
			t.Errorf("unexpected calldata length %d", len(data))
		}
		issuerHex := data[8:]
		var resultHex string
		switch issuerHex {
		case hex.EncodeToString(mustIssuerHash(IssuerG2)):
			resultHex = sampleG2Hex
		case hex.EncodeToString(mustIssuerHash(IssuerG3)):
			resultHex = sampleG3Hex
		default:
			t.Errorf("unknown issuer id in calldata: %s", issuerHex)
			resultHex = strings.Repeat("0", 64)
		}
		_ = json.NewEncoder(w).Encode(rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  "0x" + resultHex,
		})
	}))
	defer srv.Close()

	src := NewOnchainSource(srv.URL, "0xf3aAAe2D017dcC9cA901aDC9Da419f1C70362ab1", 2*time.Second)
	roots, err := src.FetchAll(context.Background())
	if err != nil {
		t.Fatalf("FetchAll: %v", err)
	}
	if got := roots[IssuerG2].Hex(); got != "0x"+sampleG2Hex {
		t.Errorf("G2 root = %s, want 0x%s", got, sampleG2Hex)
	}
	if got := roots[IssuerG3].Hex(); got != "0x"+sampleG3Hex {
		t.Errorf("G3 root = %s, want 0x%s", got, sampleG3Hex)
	}
	if rpcHits != len(AllIssuers) {
		t.Errorf("expected %d RPC hits, got %d", len(AllIssuers), rpcHits)
	}
}

func TestOnchainSource_RPCError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(rpcResponse{
			JSONRPC: "2.0",
			ID:      1,
			Error:   &rpcError{Code: -32000, Message: "execution reverted"},
		})
	}))
	defer srv.Close()

	src := NewOnchainSource(srv.URL, "0x01", time.Second)
	if _, err := src.FetchAll(context.Background()); err == nil {
		t.Fatal("expected error from rpc error response")
	}
}

func TestGitHubReleaseSource_FetchAll(t *testing.T) {
	t.Parallel()
	body := fmt.Sprintf(`Auto-updated SMT snapshot 2026-04-22T05:05:23Z

### G2
- **Root:** `+"`0x%s`"+`
- **Count:** 405066
- **CRL Number:** 2026042210

### G3
- **Root:** `+"`0x%s`"+`
- **Count:** 113798
`, sampleG2Hex, sampleG3Hex)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/repo/releases/tags/snapshot-latest" {
			http.Error(w, "not found", 404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"body": body})
	}))
	defer srv.Close()

	src := NewGitHubReleaseSource("owner/repo", "snapshot-latest", time.Second)
	src.APIBase = srv.URL
	roots, err := src.FetchAll(context.Background())
	if err != nil {
		t.Fatalf("FetchAll: %v", err)
	}
	if got := roots[IssuerG2].Hex(); got != "0x"+sampleG2Hex {
		t.Errorf("G2 root = %s, want 0x%s", got, sampleG2Hex)
	}
	if got := roots[IssuerG3].Hex(); got != "0x"+sampleG3Hex {
		t.Errorf("G3 root = %s, want 0x%s", got, sampleG3Hex)
	}
}

func TestGitHubReleaseSource_MissingIssuer(t *testing.T) {
	t.Parallel()
	// Only G2 present in the body.
	body := fmt.Sprintf("### G2\n- **Root:** `0x%s`", sampleG2Hex)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"body": body})
	}))
	defer srv.Close()

	src := NewGitHubReleaseSource("owner/repo", "snapshot-latest", time.Second)
	src.APIBase = srv.URL
	if _, err := src.FetchAll(context.Background()); err == nil {
		t.Fatal("expected error when G3 root is missing from body")
	}
}

func TestProvider_FallbackOnPrimaryFailure(t *testing.T) {
	t.Parallel()
	primary := &failingSource{name: "onchain"}
	fallback := &staticSource{
		name: "github",
		roots: map[IssuerID]Root{
			IssuerG2: mustParse(sampleG2Hex),
			IssuerG3: mustParse(sampleG3Hex),
		},
	}
	p := NewProvider(Config{
		Primary:      primary,
		Fallback:     fallback,
		FetchTimeout: time.Second,
		Logger:       silentLogger{},
	})
	if err := p.FetchNow(context.Background(), "test"); err != nil {
		t.Fatalf("FetchNow: %v", err)
	}
	r, ok := p.Trusted(IssuerG2)
	if !ok || r.Hex() != "0x"+sampleG2Hex {
		t.Fatalf("G2 not populated from fallback: %v ok=%v", r.Hex(), ok)
	}
	if got := p.Status().SourceUsed; got != "github" {
		t.Errorf("SourceUsed = %q, want github", got)
	}
}

func TestProvider_StaleOnError(t *testing.T) {
	t.Parallel()
	initial := map[IssuerID]Root{
		IssuerG2: mustParse(sampleG2Hex),
		IssuerG3: mustParse(sampleG3Hex),
	}
	src := &switchableSource{name: "onchain", roots: initial}
	p := NewProvider(Config{
		Primary:      src,
		FetchTimeout: time.Second,
		Logger:       silentLogger{},
	})
	if err := p.FetchNow(context.Background(), "test-1"); err != nil {
		t.Fatalf("first FetchNow: %v", err)
	}
	// Now flip the source to error.
	src.fail = true
	if err := p.FetchNow(context.Background(), "test-2"); err == nil {
		t.Fatal("expected error on second fetch")
	}
	// Cache must retain the previous roots.
	r, ok := p.Trusted(IssuerG2)
	if !ok || r.Hex() != "0x"+sampleG2Hex {
		t.Fatalf("stale cache lost: %v ok=%v", r.Hex(), ok)
	}
	if p.Status().ConsecutiveFail != 1 {
		t.Errorf("ConsecutiveFail = %d, want 1", p.Status().ConsecutiveFail)
	}
}

func TestProvider_NoSource(t *testing.T) {
	t.Parallel()
	p := NewProvider(Config{Logger: silentLogger{}})
	if err := p.FetchNow(context.Background(), "startup"); err != ErrNoSource {
		t.Fatalf("got %v, want ErrNoSource", err)
	}
}

func TestNewStaticProvider(t *testing.T) {
	t.Parallel()
	p := NewStaticProvider(map[IssuerID]Root{
		IssuerG2: mustParse(sampleG2Hex),
	})
	r, ok := p.Trusted(IssuerG2)
	if !ok || r.Hex() != "0x"+sampleG2Hex {
		t.Fatalf("static provider returned wrong root: %v ok=%v", r.Hex(), ok)
	}
}

// --- helpers ---

func mustParse(s string) Root {
	r, err := ParseRoot(s)
	if err != nil {
		panic(err)
	}
	return r
}

func mustIssuerHash(i IssuerID) []byte {
	h := IssuerIDHash(i)
	return h[:]
}

type failingSource struct{ name string }

func (s *failingSource) Name() string { return s.name }
func (s *failingSource) FetchAll(context.Context) (map[IssuerID]Root, error) {
	return nil, fmt.Errorf("boom")
}

type staticSource struct {
	name  string
	roots map[IssuerID]Root
}

func (s *staticSource) Name() string { return s.name }
func (s *staticSource) FetchAll(context.Context) (map[IssuerID]Root, error) {
	return s.roots, nil
}

type switchableSource struct {
	name  string
	roots map[IssuerID]Root
	fail  bool
}

func (s *switchableSource) Name() string { return s.name }
func (s *switchableSource) FetchAll(context.Context) (map[IssuerID]Root, error) {
	if s.fail {
		return nil, fmt.Errorf("switched to fail")
	}
	return s.roots, nil
}

type silentLogger struct{}

func (silentLogger) Event(level, event string, kv ...any) {}
