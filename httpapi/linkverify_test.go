package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zkmopro/go-zkid-verifier/linkverify"
	"github.com/zkmopro/go-zkid-verifier/store"
	"github.com/zkmopro/go-zkid-verifier/verifier"
)

type fakeVerifier struct {
	result *linkverify.Result
	err    error
}

func (f *fakeVerifier) Verify(linkverify.Request) (*linkverify.Result, error) {
	return f.result, f.err
}

type fakeHTTPStore struct {
	byHex     map[string]*store.Challenge
	recordErr error
}

func (s *fakeHTTPStore) CreateChallenge(ctx context.Context) (*store.Challenge, error) {
	return nil, errors.New("not used")
}
func (s *fakeHTTPStore) GetChallenge(ctx context.Context, id string) (*store.Challenge, error) {
	return nil, nil
}
func (s *fakeHTTPStore) GetChallengeByHex(ctx context.Context, hex string) (*store.Challenge, error) {
	return s.byHex[hex], nil
}
func (s *fakeHTTPStore) VerifyAndRecord(ctx context.Context, nullifier, challengeID string, proof *string, proofType string) error {
	return s.recordErr
}

func postLinkVerify(t *testing.T, h http.Handler, body LinkVerifyRequest) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest("POST", "/link-verify", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// 409 Conflict with reason=smt_root_mismatch lets clients distinguish a stale
// root from an invalid proof without inspecting the body.
func TestLinkVerify_SmtRootMismatchReturns409(t *testing.T) {
	fv := &fakeVerifier{
		result: &linkverify.Result{
			Verified: false,
			Reason:   "smt_root_mismatch",
			SmtRoot: &linkverify.SmtRootOutcome{
				IssuerName: "g2",
				Match:      false,
				Expected:   "0xaaaa",
				Observed:   "0xbbbb",
			},
		},
	}
	svc := linkverify.NewService(fv, &fakeHTTPStore{})
	h := NewRouter(svc, &fakeHTTPStore{}, nil)

	w := postLinkVerify(t, h, LinkVerifyRequest{
		CertChainType:  "rs2048",
		CertChainProof: []byte("x"),
		DeviceSigProof: []byte("x"),
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("status: got %d, want %d", w.Code, http.StatusConflict)
	}
	var resp VerifyFailResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, w.Body.String())
	}
	if resp.Verified {
		t.Error("Verified: got true, want false")
	}
	if resp.Reason != "smt_root_mismatch" {
		t.Errorf("Reason: got %q", resp.Reason)
	}
	if resp.SmtRoot == nil || resp.SmtRoot.Expected != "0xaaaa" {
		t.Errorf("SmtRoot details missing: %+v", resp.SmtRoot)
	}
}

func TestLinkVerify_ProofInvalidStays200(t *testing.T) {
	fv := &fakeVerifier{
		result: &linkverify.Result{Verified: false, Reason: "proof_invalid"},
	}
	svc := linkverify.NewService(fv, &fakeHTTPStore{})
	h := NewRouter(svc, &fakeHTTPStore{}, nil)

	w := postLinkVerify(t, h, LinkVerifyRequest{
		CertChainType:  "rs2048",
		CertChainProof: []byte("x"),
		DeviceSigProof: []byte("x"),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", w.Code, http.StatusOK)
	}
}

// 503 signals that the server can't presently verify SMT roots (upstream
// fetch failing). Clients should retry rather than treat it as a bad proof.
func TestLinkVerify_SmtRootUnavailableReturns503(t *testing.T) {
	fv := &fakeVerifier{err: linkverify.ErrSmtRootUnavailable}
	svc := linkverify.NewService(fv, &fakeHTTPStore{})
	h := NewRouter(svc, &fakeHTTPStore{}, nil)

	w := postLinkVerify(t, h, LinkVerifyRequest{
		CertChainType:  "rs2048",
		CertChainProof: []byte("x"),
		DeviceSigProof: []byte("x"),
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestLinkVerify_DuplicateNullifier409IncludesNullifier(t *testing.T) {
	parsed := &verifier.ParsedInputs{
		Challenge:     "hex1",
		SubjectDNHash: "null-123",
	}
	fv := &fakeVerifier{
		result: &linkverify.Result{Verified: true, Parsed: parsed},
	}
	fs := &fakeHTTPStore{
		byHex: map[string]*store.Challenge{
			"hex1": {ID: "cid", BytesHex: "hex1", ExpiresAt: time.Now().Add(time.Hour)},
		},
		recordErr: store.ErrDuplicateNullifier,
	}
	svc := linkverify.NewService(fv, fs)
	h := NewRouter(svc, fs, nil)

	w := postLinkVerify(t, h, LinkVerifyRequest{
		CertChainType:  "rs2048",
		CertChainProof: []byte("x"),
		DeviceSigProof: []byte("x"),
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("status: got %d, want 409", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["nullifier"] != "null-123" {
		t.Errorf("nullifier echoed: got %q, want %q", body["nullifier"], "null-123")
	}
}

