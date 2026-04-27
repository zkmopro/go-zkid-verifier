package linkverify

import (
	"context"
	"time"

	"github.com/zkmopro/go-zkid-verifier/store"
)

// Service coordinates link verification and persistence.
type Service struct {
	verifier ProofVerifier
	store    store.Store
}

// ProofVerifier verifies a link request.
type ProofVerifier interface {
	Verify(Request) (*Result, error)
}

func NewService(v ProofVerifier, s store.Store) *Service {
	return &Service{verifier: v, store: s}
}

// ProcessResult includes verifier output and persistence metadata.
type ProcessResult struct {
	*Result
	Nullifier   string
	ChallengeID string
	Persisted   bool
}

// VerifyAndRecordByProof verifies and records using challenge/nullifier from proof inputs.
func (s *Service) VerifyAndRecordByProof(ctx context.Context, req Request) (*ProcessResult, error) {
	r, err := s.verifier.Verify(req)
	if err != nil {
		return nil, err
	}
	if !r.Verified {
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

	return s.finalize(ctx, c.ID, r.Parsed.Nullifier, req.ProofType, r)
}

// VerifyAndRecordByID verifies and records using caller-provided challengeID/nullifier.
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

// finalize records the verification and returns the composed process result.
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
