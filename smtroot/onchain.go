package smtroot

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"
)

const (
	// Public Arbitrum Sepolia JSON-RPC used when SMT_ROOT_RPC_URL is unset.
	DefaultRPCURL = "https://sepolia-rollup.arbitrum.io/rpc"
	// SMTRootStorage deployment on Arbitrum Sepolia.
	DefaultContract = "0xc461326eb6e46F10A276B0F14BFFf8b256A43FFA"
)

// OnchainSource calls SMTRootStorage.getRoot via eth_call.
type OnchainSource struct {
	RPCURL   string
	Contract string
	Client   *http.Client
}

func NewOnchainSource(rpcURL, contract string, timeout time.Duration) *OnchainSource {
	if rpcURL == "" {
		rpcURL = DefaultRPCURL
	}
	if contract == "" {
		contract = DefaultContract
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &OnchainSource{
		RPCURL:   rpcURL,
		Contract: contract,
		Client:   &http.Client{Timeout: timeout},
	}
}

func (s *OnchainSource) Name() string { return "onchain" }

// FetchAll runs one eth_call per issuer in parallel. Returns a combined error
// if any issuer fails — partial results would let callers install a fake root
// for an issuer the RPC silently dropped.
func (s *OnchainSource) FetchAll(ctx context.Context) (map[IssuerID]Root, error) {
	type result struct {
		issuer IssuerID
		root   Root
		err    error
	}
	ch := make(chan result, len(AllIssuers))
	for _, issuer := range AllIssuers {
		go func(issuer IssuerID) {
			root, err := s.fetch(ctx, issuer)
			ch <- result{issuer, root, err}
		}(issuer)
	}
	out := make(map[IssuerID]Root, len(AllIssuers))
	var errs []error
	for range AllIssuers {
		r := <-ch
		if r.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.issuer.LongName(), r.err))
			continue
		}
		out[r.issuer] = r.root
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

func (s *OnchainSource) fetch(ctx context.Context, issuer IssuerID) (Root, error) {
	data := append([]byte{}, getRootSelector[:]...)
	id := IssuerIDHash(issuer)
	data = append(data, id[:]...)

	reqBody, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "eth_call",
		Params: []json.RawMessage{
			mustJSON(ethCallArgs{To: s.Contract, Data: "0x" + hex.EncodeToString(data)}),
			json.RawMessage(`"latest"`),
		},
	})
	if err != nil {
		return Root{}, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.RPCURL, bytes.NewReader(reqBody))
	if err != nil {
		return Root{}, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.Client.Do(httpReq)
	if err != nil {
		return Root{}, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return Root{}, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Root{}, fmt.Errorf("status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var rr rpcResponse
	if err := json.Unmarshal(body, &rr); err != nil {
		return Root{}, fmt.Errorf("decode response: %w", err)
	}
	if rr.Error != nil {
		return Root{}, fmt.Errorf("rpc error %d: %s", rr.Error.Code, rr.Error.Message)
	}
	hx := strings.TrimPrefix(string(rr.Result), "0x")
	if len(hx) != 64 {
		return Root{}, fmt.Errorf("unexpected result length %d: %q", len(hx), rr.Result)
	}
	return ParseRoot(hx)
}

type rpcRequest struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      int               `json:"id"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
}

type ethCallArgs struct {
	To   string `json:"to"`
	Data string `json:"data"`
}

type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      int       `json:"id"`
	Result  string    `json:"result"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Populated in init(), never mutated afterwards — read-safe without a lock.
var (
	getRootSelector [4]byte
	issuerIDCache   = map[IssuerID][32]byte{}
)

// IssuerIDHash returns keccak256(issuer.LongName()), or the zero hash for any
// IssuerID outside AllIssuers.
func IssuerIDHash(issuer IssuerID) [32]byte {
	return issuerIDCache[issuer]
}

func keccak256(data []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func init() {
	sum := keccak256([]byte("getRoot(bytes32)"))
	copy(getRootSelector[:], sum[:4])
	for _, issuer := range AllIssuers {
		issuerIDCache[issuer] = keccak256([]byte(issuer.LongName()))
	}
}
