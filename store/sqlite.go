package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS challenges (
    id          TEXT     PRIMARY KEY,
    bytes_hex   TEXT     NOT NULL,
    bytes_raw   BLOB     NOT NULL,
    issued_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    expires_at  DATETIME NOT NULL,
    consumed_at DATETIME
);

CREATE TABLE IF NOT EXISTS verifications (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    nullifier    TEXT    NOT NULL UNIQUE,
    id_verified  BOOLEAN NOT NULL DEFAULT 1,
    id_proof     TEXT,
    proof_type   TEXT    NOT NULL DEFAULT 'tbs',
    verified_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    challenge_id TEXT    NOT NULL,
    FOREIGN KEY (challenge_id) REFERENCES challenges(id)
);
`

// SQLiteStore implements Store using modernc.org/sqlite (pure Go, no CGO).
type SQLiteStore struct {
	db  *sql.DB
	ttl time.Duration
}

// NewSQLiteStore opens (or creates) a SQLite database at dbPath and runs migrations.
// Use ":memory:" for tests or t.TempDir()+"/test.db" to avoid file scatter.
func NewSQLiteStore(dbPath string, ttl time.Duration) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Single connection for the reference server. Ensures PRAGMA foreign_keys
	// is set on every connection (there's only one).
	db.SetMaxOpenConns(1)

	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	// Add proof_type column if it was created before this column existed.
	if _, err := db.Exec(`ALTER TABLE verifications ADD COLUMN proof_type TEXT NOT NULL DEFAULT 'tbs'`); err != nil {
		// SQLite returns an error if the column already exists; ignore it.
		if !strings.Contains(err.Error(), "duplicate column name") {
			db.Close()
			return nil, fmt.Errorf("migrate verifications.proof_type: %w", err)
		}
	}

	return &SQLiteStore{db: db, ttl: ttl}, nil
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) CreateChallenge(ctx context.Context) (*Challenge, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	nonce[15] &= 0xF0 // zero last nibble so BytesHex is exactly 31 hex chars

	idHash := sha256.Sum256(nonce[:])
	id := hex.EncodeToString(idHash[:16])
	bytesHex := hex.EncodeToString(nonce[:])[:31]
	expiresAt := time.Now().Add(s.ttl)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO challenges (id, bytes_hex, bytes_raw, expires_at) VALUES (?, ?, ?, ?)`,
		id, bytesHex, nonce[:], expiresAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("insert challenge: %w", err)
	}

	return &Challenge{
		ID:        id,
		Bytes:     nonce,
		BytesHex:  bytesHex,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *SQLiteStore) GetChallenge(ctx context.Context, id string) (*Challenge, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, bytes_hex, bytes_raw, expires_at FROM challenges WHERE id = ?`, id,
	)

	var c Challenge
	var rawBytes []byte
	var expiresAtStr string
	if err := row.Scan(&c.ID, &c.BytesHex, &rawBytes, &expiresAtStr); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan challenge: %w", err)
	}

	if len(rawBytes) != 16 {
		return nil, fmt.Errorf("corrupt challenge: bytes_raw has %d bytes, want 16", len(rawBytes))
	}
	copy(c.Bytes[:], rawBytes)

	expiresAt, parseErr := parseTime(expiresAtStr)
	if parseErr != nil {
		return nil, fmt.Errorf("parse expires_at: %w", parseErr)
	}
	c.ExpiresAt = expiresAt

	return &c, nil
}

func (s *SQLiteStore) GetChallengeByHex(ctx context.Context, bytesHex string) (*Challenge, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, bytes_hex, bytes_raw, expires_at FROM challenges WHERE bytes_hex = ?`, bytesHex,
	)

	var c Challenge
	var rawBytes []byte
	var expiresAtStr string
	if err := row.Scan(&c.ID, &c.BytesHex, &rawBytes, &expiresAtStr); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan challenge: %w", err)
	}

	if len(rawBytes) != 16 {
		return nil, fmt.Errorf("corrupt challenge: bytes_raw has %d bytes, want 16", len(rawBytes))
	}
	copy(c.Bytes[:], rawBytes)

	expiresAt, parseErr := parseTime(expiresAtStr)
	if parseErr != nil {
		return nil, fmt.Errorf("parse expires_at: %w", parseErr)
	}
	c.ExpiresAt = expiresAt

	return &c, nil
}

func (s *SQLiteStore) VerifyAndRecord(ctx context.Context, nullifier, challengeID string, proof *string, proofType string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Check challenge exists and read its state
	var expiresAtStr string
	var consumedAt sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT expires_at, consumed_at FROM challenges WHERE id = ?`, challengeID,
	).Scan(&expiresAtStr, &consumedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrChallengeNotFound
		}
		return fmt.Errorf("query challenge: %w", err)
	}

	// Check expiry
	expiresAt, err := parseTime(expiresAtStr)
	if err != nil {
		return fmt.Errorf("parse expires_at: %w", err)
	}
	if time.Now().After(expiresAt) {
		return ErrChallengeExpired
	}

	// Check consumed
	if consumedAt.Valid {
		return ErrChallengeConsumed
	}

	// Insert verification — UNIQUE constraint on nullifier handles duplicates
	var proofVal sql.NullString
	if proof != nil {
		proofVal = sql.NullString{String: *proof, Valid: true}
	}
	if proofType == "" {
		proofType = "tbs"
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO verifications (nullifier, id_verified, id_proof, proof_type, challenge_id) VALUES (?, 1, ?, ?, ?)`,
		nullifier, proofVal, proofType, challengeID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateNullifier
		}
		return fmt.Errorf("insert verification: %w", err)
	}

	// Mark challenge as consumed
	_, err = tx.ExecContext(ctx,
		`UPDATE challenges SET consumed_at = datetime('now') WHERE id = ?`, challengeID,
	)
	if err != nil {
		return fmt.Errorf("consume challenge: %w", err)
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetVerification(ctx context.Context, nullifier string) (*VerificationRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT nullifier, id_verified, id_proof, proof_type, verified_at, challenge_id
		 FROM verifications WHERE nullifier = ?`, nullifier,
	)

	var rec VerificationRecord
	var idProof sql.NullString
	var verifiedAtStr string
	if err := row.Scan(&rec.Nullifier, &rec.IDVerified, &idProof, &rec.ProofType, &verifiedAtStr, &rec.ChallengeID); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan verification: %w", err)
	}

	if idProof.Valid {
		rec.IDProof = &idProof.String
	}

	verifiedAt, parseErr := parseTime(verifiedAtStr)
	if parseErr != nil {
		return nil, fmt.Errorf("parse verified_at: %w", parseErr)
	}
	rec.VerifiedAt = verifiedAt

	return &rec, nil
}

// parseTime parses a time string from SQLite, always returning UTC.
// Handles both RFC3339 and SQLite's default datetime format.
func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return t.UTC(), nil
	}
	t, err = time.Parse("2006-01-02 15:04:05", s)
	if err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unrecognized time format: %q", s)
}

// isUniqueViolation checks if the error is a SQLite UNIQUE constraint violation.
func isUniqueViolation(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
