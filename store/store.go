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

// AppIDLen is the wire-format length of app_id, in bytes (31 small field
// elements in device_sig public values).
const AppIDLen = 31

// Challenge is a server-issued nonce for replay protection. The application
// signs the server's configured APP_ID; the challenge_id is what guarantees
// each session-bound proof can only be consumed once.
type Challenge struct {
	ID        string    `json:"challenge_id"`
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
	// CreateChallenge generates and persists a new challenge_id.
	CreateChallenge(ctx context.Context) (*Challenge, error)

	// GetChallenge retrieves a challenge by ID.
	// Returns nil, nil if not found. Does NOT check expiry (caller's responsibility).
	GetChallenge(ctx context.Context, id string) (*Challenge, error)

	// VerifyAndRecord atomically validates the challenge, records a verification,
	// and consumes the challenge inside a single DB transaction.
	//
	// Checks inside TX: challenge exists, not expired, not consumed, nullifier unique.
	// proofType identifies the verification method: "link_rs2048" or "link_rs4096".
	//
	// Returns sentinel errors: ErrChallengeNotFound, ErrChallengeExpired,
	// ErrChallengeConsumed, ErrDuplicateNullifier.
	VerifyAndRecord(ctx context.Context, nullifier, challengeID string, proof *string, proofType string) error

	// CleanDB wipes all rows from challenges and verifications in a single
	// transaction. Schema is preserved. Returns the number of rows deleted from
	// each table. Intended for dev/test use only — gate access at the transport
	// layer (e.g. behind a debug token).
	CleanDB(ctx context.Context) (challenges, verifications int64, err error)
}
