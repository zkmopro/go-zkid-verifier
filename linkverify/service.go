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

// VerifyAndRecord verifies the proof, checks app_id binding via the configured
// Verifier.ExpectedAppID, and on success consumes the supplied challenge_id +
// records the proof's nullifier. Both HTTP and gRPC route through here.
//
// Nullifier is derived from the proof's device_sig public values; callers do
// not provide it.
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
