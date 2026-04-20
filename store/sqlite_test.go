package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := NewSQLiteStore(":memory:", 5*time.Minute)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestNewSQLiteStore(t *testing.T) {
	s := newTestStore(t)
	if s.db == nil {
		t.Fatal("db is nil")
	}
}

func TestCreateChallenge(t *testing.T) {
	s := newTestStore(t)
	c, err := s.CreateChallenge(context.Background())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if c.ID == "" {
		t.Fatal("empty ID")
	}
	if c.BytesHex == "" || len(c.BytesHex) != 31 {
		t.Fatalf("BytesHex length: got %d, want 31", len(c.BytesHex))
	}
	if c.ExpiresAt.IsZero() {
		t.Fatal("zero ExpiresAt")
	}
}

func TestCreateChallengeConcurrent(t *testing.T) {
	s := newTestStore(t)
	var wg sync.WaitGroup
	ids := make(chan string, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := s.CreateChallenge(context.Background())
			if err != nil {
				t.Errorf("concurrent create: %v", err)
				return
			}
			ids <- c.ID
		}()
	}
	wg.Wait()
	close(ids)

	seen := make(map[string]bool)
	for id := range ids {
		if seen[id] {
			t.Fatalf("duplicate ID: %s", id)
		}
		seen[id] = true
	}
}

func TestGetChallengeFound(t *testing.T) {
	s := newTestStore(t)
	created, _ := s.CreateChallenge(context.Background())

	got, err := s.GetChallenge(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("got nil")
	}
	if got.ID != created.ID {
		t.Fatalf("ID: got %s, want %s", got.ID, created.ID)
	}
	if got.BytesHex != created.BytesHex {
		t.Fatal("BytesHex mismatch")
	}
	if got.Bytes != created.Bytes {
		t.Fatal("Bytes mismatch")
	}
}

func TestGetChallengeNotFound(t *testing.T) {
	s := newTestStore(t)
	got, err := s.GetChallenge(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for nonexistent")
	}
}

func TestGetChallengeExpiredStillReturned(t *testing.T) {
	// GetChallenge does NOT check expiry — caller's responsibility
	s, err := NewSQLiteStore(":memory:", 1*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	c, _ := s.CreateChallenge(context.Background())
	time.Sleep(5 * time.Millisecond)

	got, err := s.GetChallenge(context.Background(), c.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expired challenge should still be returned by GetChallenge")
	}
}

func TestVerifyAndRecordHappyPath(t *testing.T) {
	s := newTestStore(t)
	c, _ := s.CreateChallenge(context.Background())

	err := s.VerifyAndRecord(context.Background(), "nullifier-1", c.ID, nil, "tbs")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	rec, err := s.GetVerification(context.Background(), "nullifier-1")
	if err != nil {
		t.Fatalf("get verification: %v", err)
	}
	if rec == nil {
		t.Fatal("nil verification")
	}
	if !rec.IDVerified {
		t.Fatal("not verified")
	}
	if rec.Nullifier != "nullifier-1" {
		t.Fatalf("nullifier: got %s, want nullifier-1", rec.Nullifier)
	}
	if rec.ChallengeID != c.ID {
		t.Fatalf("challenge_id: got %s, want %s", rec.ChallengeID, c.ID)
	}
	if rec.IDProof != nil {
		t.Fatal("expected nil proof")
	}
}

func TestVerifyAndRecordWithProof(t *testing.T) {
	s := newTestStore(t)
	c, _ := s.CreateChallenge(context.Background())

	proof := "deadbeef"
	err := s.VerifyAndRecord(context.Background(), "nullifier-proof", c.ID, &proof, "tbs")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	rec, _ := s.GetVerification(context.Background(), "nullifier-proof")
	if rec.IDProof == nil || *rec.IDProof != "deadbeef" {
		t.Fatalf("proof: got %v, want 'deadbeef'", rec.IDProof)
	}
}

func TestVerifyAndRecordDuplicateNullifier(t *testing.T) {
	s := newTestStore(t)
	c1, _ := s.CreateChallenge(context.Background())
	c2, _ := s.CreateChallenge(context.Background())

	err := s.VerifyAndRecord(context.Background(), "dupe", c1.ID, nil, "tbs")
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}

	err = s.VerifyAndRecord(context.Background(), "dupe", c2.ID, nil, "tbs")
	if !errors.Is(err, ErrDuplicateNullifier) {
		t.Fatalf("expected ErrDuplicateNullifier, got: %v", err)
	}
}

func TestVerifyAndRecordChallengeNotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.VerifyAndRecord(context.Background(), "n", "nonexistent", nil, "tbs")
	if !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("expected ErrChallengeNotFound, got: %v", err)
	}
}

func TestVerifyAndRecordChallengeExpired(t *testing.T) {
	s, _ := NewSQLiteStore(":memory:", 1*time.Millisecond)
	defer s.Close()

	c, _ := s.CreateChallenge(context.Background())
	time.Sleep(5 * time.Millisecond)

	err := s.VerifyAndRecord(context.Background(), "n", c.ID, nil, "tbs")
	if !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expected ErrChallengeExpired, got: %v", err)
	}
}

func TestVerifyAndRecordChallengeConsumed(t *testing.T) {
	s := newTestStore(t)
	c, _ := s.CreateChallenge(context.Background())

	// First verify consumes the challenge
	_ = s.VerifyAndRecord(context.Background(), "first", c.ID, nil, "tbs")

	// Second attempt with different nullifier should fail with consumed
	err := s.VerifyAndRecord(context.Background(), "second", c.ID, nil, "tbs")
	if !errors.Is(err, ErrChallengeConsumed) {
		t.Fatalf("expected ErrChallengeConsumed, got: %v", err)
	}
}

func TestVerifyAndRecordTransactionRollback(t *testing.T) {
	s := newTestStore(t)
	c, _ := s.CreateChallenge(context.Background())

	// First verify succeeds
	_ = s.VerifyAndRecord(context.Background(), "exists", c.ID, nil, "tbs")

	// Create another challenge
	c2, _ := s.CreateChallenge(context.Background())

	// Try to verify with duplicate nullifier on new challenge
	err := s.VerifyAndRecord(context.Background(), "exists", c2.ID, nil, "tbs")
	if !errors.Is(err, ErrDuplicateNullifier) {
		t.Fatalf("expected ErrDuplicateNullifier, got: %v", err)
	}

	// c2 should NOT be consumed (TX rolled back)
	got, _ := s.GetChallenge(context.Background(), c2.ID)
	// Verify challenge is not consumed by checking we can still use it
	err = s.VerifyAndRecord(context.Background(), "new-nullifier", c2.ID, nil, "tbs")
	if err != nil {
		t.Fatalf("c2 should still be usable after rollback, got: %v (challenge: %+v)", err, got)
	}
}

func TestGetVerificationNotFound(t *testing.T) {
	s := newTestStore(t)
	rec, err := s.GetVerification(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if rec != nil {
		t.Fatal("expected nil")
	}
}

func TestGetVerificationTimeFormat(t *testing.T) {
	s := newTestStore(t)
	c, _ := s.CreateChallenge(context.Background())
	_ = s.VerifyAndRecord(context.Background(), "time-test", c.ID, nil, "tbs")

	rec, _ := s.GetVerification(context.Background(), "time-test")
	if rec.VerifiedAt.IsZero() {
		t.Fatal("VerifiedAt is zero")
	}
	// Should be within the last minute
	if time.Since(rec.VerifiedAt) > time.Minute {
		t.Fatalf("VerifiedAt too old: %v", rec.VerifiedAt)
	}
}

func TestConcurrentVerifySameNullifier(t *testing.T) {
	s := newTestStore(t)
	var wg sync.WaitGroup
	results := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := s.CreateChallenge(context.Background())
			if err != nil {
				results <- err
				return
			}
			results <- s.VerifyAndRecord(context.Background(), "same-nullifier", c.ID, nil, "tbs")
		}()
	}
	wg.Wait()
	close(results)

	var successes, dupes int
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrDuplicateNullifier) {
			dupes++
		} else if errors.Is(err, ErrChallengeConsumed) {
			// Also acceptable — consumed check fires before uniqueness in some orderings
		} else {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 success, got %d", successes)
	}
}

func TestForeignKeyEnforcement(t *testing.T) {
	s := newTestStore(t)
	// Try to insert a verification with a non-existent challenge_id
	// This should fail if FK enforcement is on
	err := s.VerifyAndRecord(context.Background(), "fk-test", "no-such-challenge", nil, "tbs")
	if err == nil {
		t.Fatal("expected error for FK violation")
	}
	// Should be ErrChallengeNotFound (our check catches it before FK does)
	if !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("expected ErrChallengeNotFound, got: %v", err)
	}
}
