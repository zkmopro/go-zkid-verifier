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
	Nullifier   string
	ChallengeID string
	ProofType   string
	Proof       *string
}

type fakeStore struct {
	byHex         map[string]*store.Challenge
	byID          map[string]*store.Challenge
	getHexErr     error
	getIDErr      error
	recordErr     error
	recordedCalls []recordCall
}

func (f *fakeStore) CreateChallenge(ctx context.Context) (*store.Challenge, error) {
	panic("CreateChallenge not expected in these tests")
}

func (f *fakeStore) GetChallenge(ctx context.Context, id string) (*store.Challenge, error) {
	if f.getIDErr != nil {
		return nil, f.getIDErr
	}
	return f.byID[id], nil
}

func (f *fakeStore) GetChallengeByHex(ctx context.Context, bytesHex string) (*store.Challenge, error) {
	if f.getHexErr != nil {
		return nil, f.getHexErr
	}
	return f.byHex[bytesHex], nil
}

func (f *fakeStore) VerifyAndRecord(ctx context.Context, nullifier, challengeID string, proof *string, proofType string) error {
	f.recordedCalls = append(f.recordedCalls, recordCall{
		Nullifier:   nullifier,
		ChallengeID: challengeID,
		ProofType:   proofType,
		Proof:       proof,
	})
	return f.recordErr
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

func newService(v ProofVerifier, s store.Store) *Service {
	return &Service{verifier: v, store: s}
}

func successParsed(challenge, nullifier string) *verifier.ParsedInputs {
	return &verifier.ParsedInputs{
		Challenge: challenge,
		Nullifier: nullifier,
	}
}

func futureChallenge(id, hex string) *store.Challenge {
	return &store.Challenge{
		ID:        id,
		BytesHex:  hex,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
}

func expiredChallenge(id, hex string) *store.Challenge {
	return &store.Challenge{
		ID:        id,
		BytesHex:  hex,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
}

func TestVerifyAndRecordByProof_Success(t *testing.T) {
	parsed := successParsed("deadbeef", "subject-dn-hash-123")
	fv := &fakeVerifier{
		result: &Result{Verified: true, Parsed: parsed},
	}
	c := futureChallenge("chal-id-1", "deadbeef")
	fs := &fakeStore{
		byHex: map[string]*store.Challenge{"deadbeef": c},
	}
	svc := newService(fv, fs)

	pt := ProofTypeRS2048
	pr, err := svc.VerifyAndRecordByProof(context.Background(), Request{ProofType: pt})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr == nil {
		t.Fatal("expected non-nil ProcessResult")
	}
	if !pr.Verified {
		t.Errorf("Verified: got false, want true")
	}
	if pr.Nullifier != "subject-dn-hash-123" {
		t.Errorf("Nullifier: got %q, want %q", pr.Nullifier, "subject-dn-hash-123")
	}
	if pr.ChallengeID != "chal-id-1" {
		t.Errorf("ChallengeID: got %q, want %q", pr.ChallengeID, "chal-id-1")
	}
	if !pr.Persisted {
		t.Errorf("Persisted: got false, want true")
	}
	if len(fs.recordedCalls) != 1 {
		t.Fatalf("recordedCalls: got %d, want 1", len(fs.recordedCalls))
	}
	call := fs.recordedCalls[0]
	if call.Nullifier != "subject-dn-hash-123" {
		t.Errorf("recorded Nullifier: got %q", call.Nullifier)
	}
	if call.ChallengeID != "chal-id-1" {
		t.Errorf("recorded ChallengeID: got %q", call.ChallengeID)
	}
	if call.ProofType != pt.StoreKey() {
		t.Errorf("recorded ProofType: got %q, want %q", call.ProofType, pt.StoreKey())
	}
	if call.Proof != nil {
		t.Errorf("recorded Proof: got non-nil, want nil")
	}
}

func TestVerifyAndRecordByID_Success(t *testing.T) {
	fv := &fakeVerifier{
		result: &Result{Verified: true, Parsed: successParsed("unused", "unused")},
	}
	c := futureChallenge("chal-id-2", "hexvalue")
	fs := &fakeStore{
		byID: map[string]*store.Challenge{"chal-id-2": c},
	}
	svc := newService(fv, fs)

	pt := ProofTypeRS4096
	pr, err := svc.VerifyAndRecordByID(
		context.Background(),
		"chal-id-2",
		"caller-supplied-nullifier",
		Request{ProofType: pt},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr == nil || !pr.Verified {
		t.Fatal("expected verified ProcessResult")
	}
	if pr.Nullifier != "caller-supplied-nullifier" {
		t.Errorf("Nullifier: got %q", pr.Nullifier)
	}
	if pr.ChallengeID != "chal-id-2" {
		t.Errorf("ChallengeID: got %q", pr.ChallengeID)
	}
	if !pr.Persisted {
		t.Errorf("Persisted: got false, want true")
	}
	if len(fs.recordedCalls) != 1 {
		t.Fatalf("recordedCalls: got %d, want 1", len(fs.recordedCalls))
	}
	call := fs.recordedCalls[0]
	if call.Nullifier != "caller-supplied-nullifier" {
		t.Errorf("recorded Nullifier: got %q", call.Nullifier)
	}
	if call.ChallengeID != "chal-id-2" {
		t.Errorf("recorded ChallengeID: got %q", call.ChallengeID)
	}
	if call.ProofType != pt.StoreKey() {
		t.Errorf("recorded ProofType: got %q, want %q", call.ProofType, pt.StoreKey())
	}
}

func TestVerifyAndRecordByProof_ProofInvalid(t *testing.T) {
	fv := &fakeVerifier{
		result: &Result{Verified: false, Reason: "proof_invalid"},
	}
	fs := &fakeStore{}
	svc := newService(fv, fs)

	pr, err := svc.VerifyAndRecordByProof(context.Background(), Request{ProofType: ProofTypeRS2048})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr == nil {
		t.Fatal("expected non-nil ProcessResult")
	}
	if pr.Verified {
		t.Errorf("Verified: got true, want false")
	}
	if pr.Reason != "proof_invalid" {
		t.Errorf("Reason: got %q, want %q", pr.Reason, "proof_invalid")
	}
	if pr.Nullifier != "" || pr.ChallengeID != "" {
		t.Errorf("expected empty Nullifier and ChallengeID, got %q / %q", pr.Nullifier, pr.ChallengeID)
	}
	if pr.Persisted {
		t.Errorf("Persisted: got true, want false")
	}
	if len(fs.recordedCalls) != 0 {
		t.Errorf("recordedCalls: got %d, want 0", len(fs.recordedCalls))
	}
}

func TestVerifyAndRecordByProof_SmtRootMismatch(t *testing.T) {
	outcome := &SmtRootOutcome{
		IssuerName: "ICAO",
		Match:      false,
		Expected:   "0xaaaa",
		Observed:   "0xbbbb",
	}
	fv := &fakeVerifier{
		result: &Result{Verified: false, Reason: "smt_root_mismatch", SmtRoot: outcome},
	}
	fs := &fakeStore{}
	svc := newService(fv, fs)

	pr, err := svc.VerifyAndRecordByProof(context.Background(), Request{ProofType: ProofTypeRS2048})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr == nil || pr.Verified {
		t.Fatal("expected non-verified ProcessResult")
	}
	if pr.Reason != "smt_root_mismatch" {
		t.Errorf("Reason: got %q", pr.Reason)
	}
	if pr.SmtRoot != outcome {
		t.Errorf("SmtRoot not preserved on failure result")
	}
	if len(fs.recordedCalls) != 0 {
		t.Errorf("recordedCalls: got %d, want 0", len(fs.recordedCalls))
	}
}

func TestVerifyAndRecordByID_ProofInvalid(t *testing.T) {
	c := futureChallenge("chal-id-3", "hex")
	fv := &fakeVerifier{
		result: &Result{Verified: false, Reason: "proof_invalid"},
	}
	fs := &fakeStore{
		byID: map[string]*store.Challenge{"chal-id-3": c},
	}
	svc := newService(fv, fs)

	pr, err := svc.VerifyAndRecordByID(
		context.Background(),
		"chal-id-3",
		"caller-nullifier",
		Request{ProofType: ProofTypeRS2048},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr == nil {
		t.Fatal("expected non-nil ProcessResult")
	}
	if pr.Verified {
		t.Errorf("Verified: got true, want false")
	}
	if pr.Persisted {
		t.Errorf("Persisted: got true, want false")
	}
	if pr.Nullifier != "caller-nullifier" {
		t.Errorf("Nullifier: got %q", pr.Nullifier)
	}
	if pr.ChallengeID != "chal-id-3" {
		t.Errorf("ChallengeID: got %q", pr.ChallengeID)
	}
	if len(fs.recordedCalls) != 0 {
		t.Errorf("recordedCalls: got %d, want 0", len(fs.recordedCalls))
	}
}

func TestVerifyAndRecordByProof_ChallengeNotFound(t *testing.T) {
	fv := &fakeVerifier{
		result: &Result{Verified: true, Parsed: successParsed("missinghex", "subject")},
	}
	fs := &fakeStore{
		byHex: map[string]*store.Challenge{}, // no match
	}
	svc := newService(fv, fs)

	pr, err := svc.VerifyAndRecordByProof(context.Background(), Request{ProofType: ProofTypeRS2048})
	if pr != nil {
		t.Errorf("expected nil ProcessResult, got %+v", pr)
	}
	if !errors.Is(err, store.ErrChallengeNotFound) {
		t.Fatalf("error: got %v, want ErrChallengeNotFound", err)
	}
	if len(fs.recordedCalls) != 0 {
		t.Errorf("recordedCalls: got %d, want 0", len(fs.recordedCalls))
	}
}

func TestVerifyAndRecordByProof_ChallengeExpired(t *testing.T) {
	fv := &fakeVerifier{
		result: &Result{Verified: true, Parsed: successParsed("hex", "subject")},
	}
	fs := &fakeStore{
		byHex: map[string]*store.Challenge{"hex": expiredChallenge("chal-exp", "hex")},
	}
	svc := newService(fv, fs)

	pr, err := svc.VerifyAndRecordByProof(context.Background(), Request{ProofType: ProofTypeRS2048})
	if pr != nil {
		t.Errorf("expected nil ProcessResult, got %+v", pr)
	}
	if !errors.Is(err, store.ErrChallengeExpired) {
		t.Fatalf("error: got %v, want ErrChallengeExpired", err)
	}
	if len(fs.recordedCalls) != 0 {
		t.Errorf("recordedCalls: got %d, want 0", len(fs.recordedCalls))
	}
}

func TestVerifyAndRecordByID_ChallengeNotFoundBeforeVerify(t *testing.T) {
	fv := &fakeVerifier{t: t}
	fv.failIfRun = func(tt *testing.T) {
		tt.Fatal("Verifier.Verify must not be called when challenge is missing")
	}
	fs := &fakeStore{
		byID: map[string]*store.Challenge{}, // empty
	}
	svc := newService(fv, fs)

	pr, err := svc.VerifyAndRecordByID(
		context.Background(),
		"nope",
		"nullifier",
		Request{ProofType: ProofTypeRS2048},
	)
	if pr != nil {
		t.Errorf("expected nil ProcessResult, got %+v", pr)
	}
	if !errors.Is(err, store.ErrChallengeNotFound) {
		t.Fatalf("error: got %v, want ErrChallengeNotFound", err)
	}
	if fv.called {
		t.Error("verifier was called, expected short-circuit before verify")
	}
}

func TestVerifyAndRecordByID_ChallengeExpiredBeforeVerify(t *testing.T) {
	fv := &fakeVerifier{t: t}
	fv.failIfRun = func(tt *testing.T) {
		tt.Fatal("Verifier.Verify must not be called when challenge is expired")
	}
	fs := &fakeStore{
		byID: map[string]*store.Challenge{"chal-exp": expiredChallenge("chal-exp", "hex")},
	}
	svc := newService(fv, fs)

	pr, err := svc.VerifyAndRecordByID(
		context.Background(),
		"chal-exp",
		"nullifier",
		Request{ProofType: ProofTypeRS2048},
	)
	if pr != nil {
		t.Errorf("expected nil ProcessResult, got %+v", pr)
	}
	if !errors.Is(err, store.ErrChallengeExpired) {
		t.Fatalf("error: got %v, want ErrChallengeExpired", err)
	}
	if fv.called {
		t.Error("verifier was called, expected short-circuit before verify")
	}
}

func TestVerifyAndRecordByProof_DuplicateNullifier(t *testing.T) {
	fv := &fakeVerifier{
		result: &Result{Verified: true, Parsed: successParsed("hex", "dn")},
	}
	fs := &fakeStore{
		byHex:     map[string]*store.Challenge{"hex": futureChallenge("chal-dup", "hex")},
		recordErr: store.ErrDuplicateNullifier,
	}
	svc := newService(fv, fs)

	pr, err := svc.VerifyAndRecordByProof(context.Background(), Request{ProofType: ProofTypeRS2048})
	if !errors.Is(err, store.ErrDuplicateNullifier) {
		t.Fatalf("error: got %v, want ErrDuplicateNullifier", err)
	}
	if pr == nil {
		t.Fatal("expected non-nil ProcessResult carrying nullifier for 409 body")
	}
	if pr.Nullifier != "dn" {
		t.Errorf("Nullifier: got %q, want %q", pr.Nullifier, "dn")
	}
	if pr.ChallengeID != "chal-dup" {
		t.Errorf("ChallengeID: got %q, want %q", pr.ChallengeID, "chal-dup")
	}
	if pr.Persisted {
		t.Error("Persisted: got true, want false on store error")
	}
}

func TestVerifyAndRecordByProof_ChallengeConsumed(t *testing.T) {
	fv := &fakeVerifier{
		result: &Result{Verified: true, Parsed: successParsed("hex", "dn")},
	}
	fs := &fakeStore{
		byHex:     map[string]*store.Challenge{"hex": futureChallenge("chal-consumed", "hex")},
		recordErr: store.ErrChallengeConsumed,
	}
	svc := newService(fv, fs)

	pr, err := svc.VerifyAndRecordByProof(context.Background(), Request{ProofType: ProofTypeRS2048})
	if !errors.Is(err, store.ErrChallengeConsumed) {
		t.Fatalf("error: got %v, want ErrChallengeConsumed", err)
	}
	if pr == nil {
		t.Fatal("expected non-nil ProcessResult carrying nullifier")
	}
	if pr.Nullifier != "dn" || pr.ChallengeID != "chal-consumed" {
		t.Errorf("ProcessResult ids lost: got Nullifier=%q ChallengeID=%q", pr.Nullifier, pr.ChallengeID)
	}
	if pr.Persisted {
		t.Error("Persisted: got true, want false on store error")
	}
}

func TestVerifyAndRecordByProof_VerifierError(t *testing.T) {
	fv := &fakeVerifier{
		err: errors.New("boom"),
	}
	fs := &fakeStore{}
	svc := newService(fv, fs)

	pr, err := svc.VerifyAndRecordByProof(context.Background(), Request{ProofType: ProofTypeRS2048})
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
