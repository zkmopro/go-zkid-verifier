package store

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors — handlers map these to HTTP status codes.
var (
	ErrDuplicateNullifier = errors.New("nullifier already registered")
	ErrChallengeNotFound  = errors.New("challenge not found")
	ErrChallengeExpired   = errors.New("challenge expired")
	ErrChallengeConsumed  = errors.New("challenge already consumed")
)

// Challenge represents a server-generated nonce for the ZK verification flow.
type Challenge struct {
	ID        string    `json:"challenge_id"`
	Bytes     [16]byte  `json:"-"`
	BytesHex  string    `json:"challenge_bytes"`
	ExpiresAt time.Time `json:"expires_at"`
}

// VerificationRecord holds the persistent result of a successful verification.
type VerificationRecord struct {
	Nullifier   string    `json:"nullifier"`
	IDVerified  bool      `json:"id_verified"`
	IDProof     *string   `json:"id_proof,omitempty"`
	ProofType   string    `json:"proof_type"`
	VerifiedAt  time.Time `json:"verified_at"`
	ChallengeID string    `json:"challenge_id"`
}

// Store is the combined interface for challenge + verification persistence.
// BBS teams implement this interface against their own DB.
// The SQLite implementation in sqlite.go is the reference.
type Store interface {
	// CreateChallenge generates and persists a new 32-byte challenge nonce.
	CreateChallenge(ctx context.Context) (*Challenge, error)

	// GetChallenge retrieves a challenge by ID.
	// Returns nil, nil if not found. Does NOT check expiry (caller's responsibility).
	GetChallenge(ctx context.Context, id string) (*Challenge, error)

	// GetChallengeByHex retrieves a challenge by its hex value (bytes_hex column).
	// Returns nil, nil if not found. Does NOT check expiry (caller's responsibility).
	GetChallengeByHex(ctx context.Context, bytesHex string) (*Challenge, error)

	// VerifyAndRecord atomically validates the challenge, records a verification,
	// and consumes the challenge inside a single DB transaction.
	//
	// Checks inside TX: challenge exists, not expired, not consumed, nullifier unique.
	// proofType identifies the verification method: "link_rs2048" or "link_rs4096".
	//
	// Returns sentinel errors: ErrChallengeNotFound, ErrChallengeExpired,
	// ErrChallengeConsumed, ErrDuplicateNullifier.
	VerifyAndRecord(ctx context.Context, nullifier, challengeID string, proof *string, proofType string) error
}
