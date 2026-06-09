package linkverify

import (
	"context"
	"fmt"
	"time"

	"github.com/privacy-ethereum/go-zkid-verifier/store"
	"github.com/privacy-ethereum/go-zkid-verifier/verifier"
)

type Service struct {
	verifier ProofVerifier
	store    store.Store
}

type ProofVerifier interface {
	Verify(Request) (*Result, error)
	CheckChallenge(parsed *verifier.ParsedInputs, expected string) *ChallengeOutcome
}

func NewService(v ProofVerifier, s store.Store) *Service {
	return &Service{verifier: v, store: s}
}

type ProcessResult struct {
	*Result
	Nullifier string
	Persisted bool
}

// Early-rejects expired challenges to skip the (expensive) FFI verify; the
// in-TX expiry check inside store.VerifyAndRecord remains authoritative.
func (s *Service) VerifyAndRecord(
	ctx context.Context,
	req Request,
) (*ProcessResult, error) {

	r, err := s.verifier.Verify(req)
	if err != nil {
		return nil, err
	}
	if !r.Verified {
		nullifier := ""
		if r.Parsed != nil {
			nullifier = r.Parsed.Nullifier
		}
		return &ProcessResult{Result: r, Nullifier: nullifier}, nil
	}

	// Normalise the circuit's challenge signal (may be hex) to decimal for
	// consistent store key lookup.
	partial := &ProcessResult{Result: r, Nullifier: r.Parsed.Nullifier}
	challengeKey, err := verifier.NormalizeDecimal(r.Parsed.Challenge)
	if err != nil {
		return partial, fmt.Errorf("challenge signal: %w", err)
	}
	c, err := s.store.GetChallenge(ctx, challengeKey)
	if err != nil {
		return partial, err
	}
	if c == nil {
		return partial, store.ErrChallengeNotFound
	}
	if time.Now().After(c.ExpiresAt) {
		return partial, store.ErrChallengeExpired
	}
	outcome := s.verifier.CheckChallenge(r.Parsed, challengeKey)
	r.Challenge = outcome
	if !outcome.Match {
		r.Verified = false
		r.Reason = ReasonChallengeMismatch
		return &ProcessResult{Result: r, Nullifier: r.Parsed.Nullifier}, nil
	}

	return s.finalize(ctx, challengeKey, r.Parsed.Nullifier, req.ProofType, r)
}

func (s *Service) finalize(
	ctx context.Context,
	challenge, nullifier string,
	pt ProofType,
	r *Result,
) (*ProcessResult, error) {
	res := &ProcessResult{Result: r, Nullifier: nullifier}
	if err := s.store.VerifyAndRecord(ctx, nullifier, challenge, nil, pt.StoreKey()); err != nil {
		return res, err
	}
	res.Persisted = true
	return res, nil
}
