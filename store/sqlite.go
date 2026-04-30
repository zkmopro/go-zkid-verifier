package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"math/big"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS challenges (
    challenge   TEXT     PRIMARY KEY,
    issued_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    expires_at  DATETIME NOT NULL,
    consumed_at DATETIME
);

CREATE TABLE IF NOT EXISTS verifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    nullifier   TEXT    NOT NULL UNIQUE,
    id_verified BOOLEAN NOT NULL DEFAULT 1,
    id_proof    TEXT,
    proof_type  TEXT    NOT NULL DEFAULT 'tbs',
    verified_at DATETIME NOT NULL DEFAULT (datetime('now')),
    challenge   TEXT    NOT NULL,
    FOREIGN KEY (challenge) REFERENCES challenges(challenge)
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

	// Idempotent ALTER for older databases. SQLite returns "duplicate column
	// name" when the column already exists; ignore that, surface anything else.
	if _, err := db.Exec(`ALTER TABLE verifications ADD COLUMN proof_type TEXT NOT NULL DEFAULT 'tbs'`); err != nil {
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
	var seed [16]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("generate challenge seed: %w", err)
	}
	// 16 random bytes interpreted big-endian as a decimal field-element
	// string. Used as both the session lookup key and the value bound into
	// the device-sig proof.
	challenge := new(big.Int).SetBytes(seed[:]).String()
	expiresAt := time.Now().Add(s.ttl)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO challenges (challenge, expires_at) VALUES (?, ?)`,
		challenge, expiresAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("insert challenge: %w", err)
	}

	return &Challenge{Challenge: challenge, ExpiresAt: expiresAt}, nil
}

func (s *SQLiteStore) GetChallenge(ctx context.Context, challenge string) (*Challenge, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT challenge, expires_at FROM challenges WHERE challenge = ?`, challenge,
	)
	var c Challenge
	var expiresAtStr string
	if err := row.Scan(&c.Challenge, &expiresAtStr); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan challenge: %w", err)
	}
	expiresAt, parseErr := parseTime(expiresAtStr)
	if parseErr != nil {
		return nil, fmt.Errorf("parse expires_at: %w", parseErr)
	}
	c.ExpiresAt = expiresAt
	return &c, nil
}

func (s *SQLiteStore) VerifyAndRecord(ctx context.Context, nullifier, challenge string, proof *string, proofType string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var expiresAtStr string
	var consumedAt sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT expires_at, consumed_at FROM challenges WHERE challenge = ?`, challenge,
	).Scan(&expiresAtStr, &consumedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrChallengeNotFound
		}
		return fmt.Errorf("query challenge: %w", err)
	}

	expiresAt, err := parseTime(expiresAtStr)
	if err != nil {
		return fmt.Errorf("parse expires_at: %w", err)
	}
	if time.Now().After(expiresAt) {
		return ErrChallengeExpired
	}
	if consumedAt.Valid {
		return ErrChallengeConsumed
	}

	var proofVal sql.NullString
	if proof != nil {
		proofVal = sql.NullString{String: *proof, Valid: true}
	}
	if proofType == "" {
		proofType = "tbs"
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO verifications (nullifier, id_verified, id_proof, proof_type, challenge) VALUES (?, 1, ?, ?, ?)`,
		nullifier, proofVal, proofType, challenge,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateNullifier
		}
		return fmt.Errorf("insert verification: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`UPDATE challenges SET consumed_at = datetime('now') WHERE challenge = ?`, challenge,
	)
	if err != nil {
		return fmt.Errorf("consume challenge: %w", err)
	}

	return tx.Commit()
}

// CleanDB wipes all rows from verifications and challenges in a single
// transaction. Verifications are deleted first to satisfy the FK from
// verifications.challenge → challenges.challenge. Schema is preserved.
func (s *SQLiteStore) CleanDB(ctx context.Context) (int64, int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	rv, err := tx.ExecContext(ctx, `DELETE FROM verifications`)
	if err != nil {
		return 0, 0, fmt.Errorf("delete verifications: %w", err)
	}
	rc, err := tx.ExecContext(ctx, `DELETE FROM challenges`)
	if err != nil {
		return 0, 0, fmt.Errorf("delete challenges: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit: %w", err)
	}

	nv, _ := rv.RowsAffected()
	nc, _ := rc.RowsAffected()
	return nc, nv, nil
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
