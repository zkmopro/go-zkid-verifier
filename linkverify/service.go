package linkverify

import (
	"context"
	"time"

	"github.com/zkmopro/go-zkid-verifier/store"
)

type Service struct {
	verifier ProofVerifier
	store    store.Store
}

type ProofVerifier interface {
	Verify(Request) (*Result, error)
}

func NewService(v ProofVerifier, s store.Store) *Service {
	return &Service{verifier: v, store: s}
}

type ProcessResult struct {
	*Result
	Nullifier   string
	ChallengeID string
	Persisted   bool
}

// Early-rejects expired challenges to skip the (expensive) FFI verify; the
// in-TX expiry check inside store.VerifyAndRecord remains authoritative.
func (s *Service) VerifyAndRecord(
	ctx context.Context,
	challengeID string,
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
		nullifier := ""
		if r.Parsed != nil {
			nullifier = r.Parsed.Nullifier
		}
		return &ProcessResult{
			Result:      r,
			Nullifier:   nullifier,
			ChallengeID: challengeID,
		}, nil
	}

	return s.finalize(ctx, challengeID, r.Parsed.Nullifier, req.ProofType, r)
}

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
