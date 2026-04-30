package linkverify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zkmopro/go-zkid-verifier/store"
	"github.com/zkmopro/go-zkid-verifier/verifier"
)

type recordCall struct {
	Nullifier string
	Challenge string
	ProofType string
	Proof     *string
}

type fakeStore struct {
	byID          map[string]*store.Challenge
	getIDErr      error
	recordErr     error
	recordedCalls []recordCall
}

func (f *fakeStore) CreateChallenge(ctx context.Context) (*store.Challenge, error) {
	panic("CreateChallenge not expected in these tests")
}

func (f *fakeStore) GetChallenge(ctx context.Context, challenge string) (*store.Challenge, error) {
	if f.getIDErr != nil {
		return nil, f.getIDErr
	}
	return f.byID[challenge], nil
}

func (f *fakeStore) VerifyAndRecord(ctx context.Context, nullifier, challenge string, proof *string, proofType string) error {
	f.recordedCalls = append(f.recordedCalls, recordCall{
		Nullifier: nullifier,
		Challenge: challenge,
		ProofType: proofType,
		Proof:     proof,
	})
	return f.recordErr
}

func (f *fakeStore) CleanDB(ctx context.Context) (int64, int64, error) {
	return 0, 0, nil
}

type fakeVerifier struct {
	result    *Result
	err       error
	called    bool
	failIfRun func(*testing.T)
	t         *testing.T
}

func (f *fakeVerifier) Verify(Request) (*Result, error) {
	f.called = true
	if f.failIfRun != nil {
		f.failIfRun(f.t)
	}
	return f.result, f.err
}

// Match-by-default for the broader fake-verifier suite; tests that target the
// mismatch path use httpapi/linkverify_test.go::TestLinkVerify_ChallengeMismatchReturns409
// or the real-FFI counterpart in linkverify_test.go.
func (f *fakeVerifier) CheckChallenge(parsed *verifier.ParsedInputs, expected string) *ChallengeOutcome {
	return &ChallengeOutcome{Match: true, Expected: expected, Observed: parsed.Challenge}
}

func newService(v ProofVerifier, s store.Store) *Service {
	return &Service{verifier: v, store: s}
}

func successParsed(appID, nullifier string) *verifier.ParsedInputs {
	return &verifier.ParsedInputs{
		AppID:     appID,
		Nullifier: nullifier,
	}
}

func futureChallenge(challenge string) *store.Challenge {
	return &store.Challenge{Challenge: challenge, ExpiresAt: time.Now().Add(1 * time.Hour)}
}

func expiredChallenge(challenge string) *store.Challenge {
	return &store.Challenge{Challenge: challenge, ExpiresAt: time.Now().Add(-1 * time.Hour)}
}

func TestVerifyAndRecord_Success(t *testing.T) {
	parsed := successParsed("0xappid", "n-1")
	fv := &fakeVerifier{
		result: &Result{Verified: true, Parsed: parsed},
	}
	c := futureChallenge("chal-1")
	fs := &fakeStore{byID: map[string]*store.Challenge{c.Challenge: c}}
	svc := newService(fv, fs)

	pt := ProofTypeRS2048
	pr, err := svc.VerifyAndRecord(context.Background(), c.Challenge, Request{ProofType: pt})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr == nil || !pr.Verified {
		t.Fatal("expected verified ProcessResult")
	}
	if pr.Nullifier != "n-1" {
		t.Errorf("Nullifier: got %q", pr.Nullifier)
	}
	if !pr.Persisted {
		t.Error("Persisted: got false")
	}
	if len(fs.recordedCalls) != 1 {
		t.Fatalf("recordedCalls: got %d, want 1", len(fs.recordedCalls))
	}
	call := fs.recordedCalls[0]
	if call.Nullifier != "n-1" || call.Challenge != c.Challenge || call.ProofType != pt.StoreKey() {
		t.Errorf("recorded call: got %+v", call)
	}
}

func TestVerifyAndRecord_ChallengeNotFound(t *testing.T) {
	fv := &fakeVerifier{t: t}
	fv.failIfRun = func(tt *testing.T) {
		tt.Fatal("Verifier.Verify must not run when challenge is missing")
	}
	fs := &fakeStore{byID: map[string]*store.Challenge{}}
	svc := newService(fv, fs)

	pr, err := svc.VerifyAndRecord(context.Background(), "nope", Request{ProofType: ProofTypeRS2048})
	if pr != nil {
		t.Errorf("expected nil ProcessResult, got %+v", pr)
	}
	if !errors.Is(err, store.ErrChallengeNotFound) {
		t.Fatalf("error: got %v, want ErrChallengeNotFound", err)
	}
	if fv.called {
		t.Error("verifier was called; expected short-circuit before verify")
	}
}

func TestVerifyAndRecord_ChallengeExpired(t *testing.T) {
	fv := &fakeVerifier{t: t}
	fv.failIfRun = func(tt *testing.T) {
		tt.Fatal("Verifier.Verify must not run when challenge is expired")
	}
	c := expiredChallenge("c-exp")
	fs := &fakeStore{byID: map[string]*store.Challenge{c.Challenge: c}}
	svc := newService(fv, fs)

	pr, err := svc.VerifyAndRecord(context.Background(), c.Challenge, Request{ProofType: ProofTypeRS2048})
	if pr != nil {
		t.Errorf("expected nil ProcessResult, got %+v", pr)
	}
	if !errors.Is(err, store.ErrChallengeExpired) {
		t.Fatalf("error: got %v, want ErrChallengeExpired", err)
	}
	if fv.called {
		t.Error("verifier was called; expected short-circuit before verify")
	}
}

func TestVerifyAndRecord_ProofInvalid(t *testing.T) {
	c := futureChallenge("c-3")
	fv := &fakeVerifier{
		result: &Result{Verified: false, Reason: "proof_invalid"},
	}
	fs := &fakeStore{byID: map[string]*store.Challenge{c.Challenge: c}}
	svc := newService(fv, fs)

	pr, err := svc.VerifyAndRecord(context.Background(), c.Challenge, Request{ProofType: ProofTypeRS2048})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr == nil || pr.Verified {
		t.Fatalf("expected non-verified ProcessResult, got %+v", pr)
	}
	if pr.Reason != "proof_invalid" {
		t.Errorf("Reason: got %q", pr.Reason)
	}
	if pr.Persisted {
		t.Error("Persisted: got true")
	}
	if len(fs.recordedCalls) != 0 {
		t.Errorf("recordedCalls: got %d, want 0", len(fs.recordedCalls))
	}
}

func TestVerifyAndRecord_AppIDMismatchNotPersisted(t *testing.T) {
	c := futureChallenge("c-am")
	outcome := &AppIDOutcome{Match: false, Expected: "0xexpected", Observed: "0xobserved"}
	fv := &fakeVerifier{
		result: &Result{
			Verified: false,
			Reason:   ReasonAppIDMismatch,
			Parsed:   successParsed("0xobserved", "n-app"),
			AppID:    outcome,
		},
	}
	fs := &fakeStore{byID: map[string]*store.Challenge{c.Challenge: c}}
	svc := newService(fv, fs)

	pr, err := svc.VerifyAndRecord(context.Background(), c.Challenge, Request{ProofType: ProofTypeRS2048})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr == nil || pr.Verified {
		t.Fatalf("expected non-verified ProcessResult, got %+v", pr)
	}
	if pr.Reason != ReasonAppIDMismatch {
		t.Errorf("Reason: got %q, want %q", pr.Reason, ReasonAppIDMismatch)
	}
	if pr.AppID != outcome {
		t.Errorf("AppID outcome not preserved")
	}
	if pr.Nullifier != "n-app" {
		t.Errorf("Nullifier: got %q, want carry-through from parsed", pr.Nullifier)
	}
	if pr.Persisted {
		t.Error("Persisted: got true on mismatch")
	}
	if len(fs.recordedCalls) != 0 {
		t.Errorf("recordedCalls: got %d, want 0 (must not consume challenge on mismatch)", len(fs.recordedCalls))
	}
}

func TestVerifyAndRecord_DuplicateNullifier(t *testing.T) {
	c := futureChallenge("c-dup")
	fv := &fakeVerifier{
		result: &Result{Verified: true, Parsed: successParsed("0xappid", "dup")},
	}
	fs := &fakeStore{
		byID:      map[string]*store.Challenge{c.Challenge: c},
		recordErr: store.ErrDuplicateNullifier,
	}
	svc := newService(fv, fs)

	pr, err := svc.VerifyAndRecord(context.Background(), c.Challenge, Request{ProofType: ProofTypeRS2048})
	if !errors.Is(err, store.ErrDuplicateNullifier) {
		t.Fatalf("error: got %v, want ErrDuplicateNullifier", err)
	}
	if pr == nil || pr.Nullifier != "dup" {
		t.Fatalf("expected ProcessResult with nullifier carry-through, got %+v", pr)
	}
	if pr.Persisted {
		t.Error("Persisted: got true on store error")
	}
}

func TestVerifyAndRecord_VerifierError(t *testing.T) {
	c := futureChallenge("c-err")
	fv := &fakeVerifier{err: errors.New("boom")}
	fs := &fakeStore{byID: map[string]*store.Challenge{c.Challenge: c}}
	svc := newService(fv, fs)

	pr, err := svc.VerifyAndRecord(context.Background(), c.Challenge, Request{ProofType: ProofTypeRS2048})
	if pr != nil {
		t.Errorf("expected nil ProcessResult, got %+v", pr)
	}
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error: got %v, want error containing %q", err, "boom")
	}
	if len(fs.recordedCalls) != 0 {
		t.Errorf("recordedCalls: got %d, want 0", len(fs.recordedCalls))
	}
}
