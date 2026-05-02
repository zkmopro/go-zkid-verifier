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

// Match-by-default: tests that exercise the mismatch path stuff parsed.Challenge
// with a value distinct from the stored challenge. See
// TestLinkVerify_ChallengeMismatchReturns409.
func (f *fakeVerifier) CheckChallenge(parsed *verifier.ParsedInputs, expected string) *linkverify.ChallengeOutcome {
	if parsed.Challenge != "" && parsed.Challenge != expected {
		return &linkverify.ChallengeOutcome{Match: false, Expected: expected, Observed: parsed.Challenge}
	}
	return &linkverify.ChallengeOutcome{Match: true, Expected: expected, Observed: parsed.Challenge}
}

type fakeHTTPStore struct {
	byID      map[string]*store.Challenge
	recordErr error
}

func (s *fakeHTTPStore) CreateChallenge(ctx context.Context) (*store.Challenge, error) {
	return nil, errors.New("not used")
}
func (s *fakeHTTPStore) GetChallenge(ctx context.Context, challenge string) (*store.Challenge, error) {
	return s.byID[challenge], nil
}
func (s *fakeHTTPStore) VerifyAndRecord(ctx context.Context, nullifier, challenge string, proof *string, proofType string) error {
	return s.recordErr
}
func (s *fakeHTTPStore) CleanDB(ctx context.Context) (int64, int64, error) {
	return 0, 0, nil
}

func futureChallenge(challenge string) *store.Challenge {
	return &store.Challenge{Challenge: challenge, ExpiresAt: time.Now().Add(time.Hour)}
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

func validReq() LinkVerifyRequest {
	return LinkVerifyRequest{
		CertChainType:  "rs2048",
		CertChainProof: []byte("x"),
		DeviceSigProof: []byte("x"),
	}
}


func TestLinkVerify_SmtRootMismatchReturns409(t *testing.T) {
	c := futureChallenge("c-1")
	fv := &fakeVerifier{
		result: &linkverify.Result{
			Verified: false,
			Reason:   linkverify.ReasonSmtRootMismatch,
			Parsed:   &verifier.ParsedInputs{Nullifier: "n"},
			SmtRoot: &linkverify.SmtRootOutcome{
				IssuerName: "g2",
				Match:      false,
				Expected:   "0xaaaa",
				Observed:   "0xbbbb",
			},
		},
	}
	fs := &fakeHTTPStore{byID: map[string]*store.Challenge{c.Challenge: c}}
	h := NewRouter(linkverify.NewService(fv, fs), fs, nil, nil, testAppID, "")

	w := postLinkVerify(t, h, validReq())
	if w.Code != http.StatusConflict {
		t.Fatalf("status: got %d, want %d", w.Code, http.StatusConflict)
	}
	var resp VerifyFailResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, w.Body.String())
	}
	if resp.Reason != linkverify.ReasonSmtRootMismatch {
		t.Errorf("Reason: got %q", resp.Reason)
	}
	if resp.SmtRoot == nil || resp.SmtRoot.Expected != "0xaaaa" {
		t.Errorf("SmtRoot details missing: %+v", resp.SmtRoot)
	}
}

func TestLinkVerify_ProofInvalidStays200(t *testing.T) {
	c := futureChallenge("c-2")
	fv := &fakeVerifier{
		result: &linkverify.Result{Verified: false, Reason: linkverify.ReasonProofInvalid},
	}
	fs := &fakeHTTPStore{byID: map[string]*store.Challenge{c.Challenge: c}}
	h := NewRouter(linkverify.NewService(fv, fs), fs, nil, nil, testAppID, "")

	w := postLinkVerify(t, h, validReq())
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
}

func TestLinkVerify_SmtRootUnavailableReturns503(t *testing.T) {
	c := futureChallenge("c-3")
	fv := &fakeVerifier{err: linkverify.ErrSmtRootUnavailable}
	fs := &fakeHTTPStore{byID: map[string]*store.Challenge{c.Challenge: c}}
	h := NewRouter(linkverify.NewService(fv, fs), fs, nil, nil, testAppID, "")

	w := postLinkVerify(t, h, validReq())
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503", w.Code)
	}
}

func TestLinkVerify_AppIDMismatchReturns409(t *testing.T) {
	c := futureChallenge("c-4")
	fv := &fakeVerifier{
		result: &linkverify.Result{
			Verified: false,
			Reason:   linkverify.ReasonAppIDMismatch,
			Parsed:   &verifier.ParsedInputs{Nullifier: "n"},
			AppID: &linkverify.AppIDOutcome{
				Match:    false,
				Expected: "0xexpected",
				Observed: "0xobserved",
			},
		},
	}
	fs := &fakeHTTPStore{byID: map[string]*store.Challenge{c.Challenge: c}}
	h := NewRouter(linkverify.NewService(fv, fs), fs, nil, nil, testAppID, "")

	w := postLinkVerify(t, h, validReq())
	if w.Code != http.StatusConflict {
		t.Fatalf("status: got %d, want 409", w.Code)
	}
	var resp VerifyFailResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, w.Body.String())
	}
	if resp.Reason != linkverify.ReasonAppIDMismatch {
		t.Errorf("Reason: got %q", resp.Reason)
	}
	if resp.AppID == nil || resp.AppID.Match {
		t.Errorf("AppID outcome: %+v", resp.AppID)
	}
}

func TestLinkVerify_ChallengeNotFoundReturns404(t *testing.T) {
	fv := &fakeVerifier{
		result: &linkverify.Result{
			Verified: true,
			Parsed:   &verifier.ParsedInputs{Nullifier: "n", Challenge: "no-such-challenge"},
		},
	}
	fs := &fakeHTTPStore{byID: map[string]*store.Challenge{}}
	h := NewRouter(linkverify.NewService(fv, fs), fs, nil, nil, testAppID, "")

	w := postLinkVerify(t, h, validReq())
	if w.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] == "" {
		t.Errorf("expected error field in body: %s", w.Body.String())
	}
}

// A proof whose bound challenge is not in the store is rejected with 404.
// (Stale or replayed proofs hit this path before the nullifier is recorded.)
func TestLinkVerify_UnknownChallengeReturns404(t *testing.T) {
	parsed := &verifier.ParsedInputs{
		Nullifier: "n-stale",
		Challenge: "999", // not in store
	}
	fv := &fakeVerifier{
		result: &linkverify.Result{Verified: true, Parsed: parsed},
	}
	fs := &fakeHTTPStore{byID: map[string]*store.Challenge{}}
	h := NewRouter(linkverify.NewService(fv, fs), fs, nil, nil, testAppID, "")

	w := postLinkVerify(t, h, validReq())
	if w.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404", w.Code)
	}
}

func TestLinkVerify_DuplicateNullifier409IncludesNullifier(t *testing.T) {
	c := futureChallenge("c-dup")
	parsed := &verifier.ParsedInputs{
		AppID:     "0xappid",
		Nullifier: "null-123",
		Challenge: c.Challenge,
	}
	fv := &fakeVerifier{
		result: &linkverify.Result{Verified: true, Parsed: parsed},
	}
	fs := &fakeHTTPStore{
		byID:      map[string]*store.Challenge{c.Challenge: c},
		recordErr: store.ErrDuplicateNullifier,
	}
	h := NewRouter(linkverify.NewService(fv, fs), fs, nil, nil, testAppID, "")

	w := postLinkVerify(t, h, validReq())
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
