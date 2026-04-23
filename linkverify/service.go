package linkverify

import (
	"context"
	"time"

	"github.com/zkmopro/go-zkid-verifier/store"
)

// Service is the single source of truth for the link-verify pipeline:
// verify proof -> challenge lookup -> expiry check -> record. HTTP and gRPC
// transports pick different method variants to get their respective semantics
// (HTTP derives challenge+nullifier from the proof; gRPC trusts the caller).
type Service struct {
	verifier ProofVerifier
	store    store.Store
}

// ProofVerifier is exported so tests in sibling packages can inject fakes.
type ProofVerifier interface {
	Verify(Request) (*Result, error)
}

func NewService(v ProofVerifier, s store.Store) *Service {
	return &Service{verifier: v, store: s}
}

// ProcessResult embeds *Result so transports can reuse its fields unchanged.
// Persisted is true only when Store.VerifyAndRecord succeeded on this call.
type ProcessResult struct {
	*Result
	Nullifier   string
	ChallengeID string
	Persisted   bool
}

// VerifyAndRecordByProof is the HTTP semantics path: challenge and nullifier
// are derived from the proof's parsed inputs. On verifier failure the
// challenge is not consumed. Order: verify -> GetChallengeByHex -> expiry -> record.
func (s *Service) VerifyAndRecordByProof(ctx context.Context, req Request) (*ProcessResult, error) {
	r, err := s.verifier.Verify(req)
	if err != nil {
		return nil, err
	}
	if !r.Verified {
		// Parsed is nil on !Verified, so the HTTP path returns empty
		// Nullifier/ChallengeID. gRPC's by-ID path echoes caller inputs instead.
		return &ProcessResult{Result: r}, nil
	}

	c, err := s.store.GetChallengeByHex(ctx, r.Parsed.Challenge)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, store.ErrChallengeNotFound
	}
	if time.Now().After(c.ExpiresAt) {
		return nil, store.ErrChallengeExpired
	}

	return s.finalize(ctx, c.ID, r.Parsed.SubjectDNHash, req.ProofType, r)
}

// VerifyAndRecordByID is the gRPC semantics path: caller supplies challengeID
// and nullifier. Lookup-first ordering pre-validates before incurring FFI cost.
// Order: GetChallenge -> expiry -> verify -> record.
func (s *Service) VerifyAndRecordByID(
	ctx context.Context,
	challengeID, nullifier string,
	req Request,
) (*ProcessResult, error) {
	c, err := s.store.GetChallenge(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, store.ErrChallengeNotFound
	}
	if time.Now().After(c.ExpiresAt) {
		return nil, store.ErrChallengeExpired
	}

	r, err := s.verifier.Verify(req)
	if err != nil {
		return nil, err
	}
	if !r.Verified {
		return &ProcessResult{
			Result:      r,
			Nullifier:   nullifier,
			ChallengeID: challengeID,
		}, nil
	}

	return s.finalize(ctx, challengeID, nullifier, req.ProofType, r)
}

// finalize records the verification. On store error the returned ProcessResult
// still carries Nullifier and ChallengeID so transports can echo them in 409
// bodies; store sentinel errors bubble unwrapped for transport mapping.
func (s *Service) finalize(
	ctx context.Context,
	challengeID, nullifier string,
	pt ProofType,
	r *Result,
) (*ProcessResult, error) {
	res := &ProcessResult{
		Result:      r,
		Nullifier:   nullifier,
		ChallengeID: challengeID,
	}
	if err := s.store.VerifyAndRecord(ctx, nullifier, challengeID, nil, pt.StoreKey()); err != nil {
		return res, err
	}
	res.Persisted = true
	return res, nil
}
