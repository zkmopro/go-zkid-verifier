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

	if err := s.VerifyAndRecord(context.Background(), "nullifier-1", c.ID, nil, "link_rs2048"); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyAndRecordDuplicateNullifier(t *testing.T) {
	s := newTestStore(t)
	c1, _ := s.CreateChallenge(context.Background())
	c2, _ := s.CreateChallenge(context.Background())

	if err := s.VerifyAndRecord(context.Background(), "dupe", c1.ID, nil, "link_rs2048"); err != nil {
		t.Fatalf("first verify: %v", err)
	}

	err := s.VerifyAndRecord(context.Background(), "dupe", c2.ID, nil, "link_rs2048")
	if !errors.Is(err, ErrDuplicateNullifier) {
		t.Fatalf("expected ErrDuplicateNullifier, got: %v", err)
	}
}

func TestVerifyAndRecordChallengeNotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.VerifyAndRecord(context.Background(), "n", "nonexistent", nil, "link_rs2048")
	if !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("expected ErrChallengeNotFound, got: %v", err)
	}
}

func TestVerifyAndRecordChallengeExpired(t *testing.T) {
	s, _ := NewSQLiteStore(":memory:", 1*time.Millisecond)
	defer s.Close()

	c, _ := s.CreateChallenge(context.Background())
	time.Sleep(5 * time.Millisecond)

	err := s.VerifyAndRecord(context.Background(), "n", c.ID, nil, "link_rs2048")
	if !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expected ErrChallengeExpired, got: %v", err)
	}
}

func TestVerifyAndRecordChallengeConsumed(t *testing.T) {
	s := newTestStore(t)
	c, _ := s.CreateChallenge(context.Background())

	// First verify consumes the challenge
	_ = s.VerifyAndRecord(context.Background(), "first", c.ID, nil, "link_rs2048")

	// Second attempt with different nullifier should fail with consumed
	err := s.VerifyAndRecord(context.Background(), "second", c.ID, nil, "link_rs2048")
	if !errors.Is(err, ErrChallengeConsumed) {
		t.Fatalf("expected ErrChallengeConsumed, got: %v", err)
	}
}

func TestVerifyAndRecordTransactionRollback(t *testing.T) {
	s := newTestStore(t)
	c, _ := s.CreateChallenge(context.Background())

	// First verify succeeds
	_ = s.VerifyAndRecord(context.Background(), "exists", c.ID, nil, "link_rs2048")

	// Create another challenge
	c2, _ := s.CreateChallenge(context.Background())

	// Try to verify with duplicate nullifier on new challenge
	err := s.VerifyAndRecord(context.Background(), "exists", c2.ID, nil, "link_rs2048")
	if !errors.Is(err, ErrDuplicateNullifier) {
		t.Fatalf("expected ErrDuplicateNullifier, got: %v", err)
	}

	// c2 should NOT be consumed (TX rolled back) — a fresh nullifier must still succeed.
	if err := s.VerifyAndRecord(context.Background(), "new-nullifier", c2.ID, nil, "link_rs2048"); err != nil {
		t.Fatalf("c2 should still be usable after rollback, got: %v", err)
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
			results <- s.VerifyAndRecord(context.Background(), "same-nullifier", c.ID, nil, "link_rs2048")
		}()
	}
	wg.Wait()
	close(results)

	var successes int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrDuplicateNullifier), errors.Is(err, ErrChallengeConsumed):
			// Both are valid losers in the race.
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 success, got %d", successes)
	}
}

func TestForeignKeyEnforcement(t *testing.T) {
	s := newTestStore(t)
	// Non-existent challenge_id should error out. Our challenge-exists check
	// fires before the FK violation, so we expect ErrChallengeNotFound.
	err := s.VerifyAndRecord(context.Background(), "fk-test", "no-such-challenge", nil, "link_rs2048")
	if !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("expected ErrChallengeNotFound, got: %v", err)
	}
}
