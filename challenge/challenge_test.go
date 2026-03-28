package challenge

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func setupServer(t *testing.T, ttl time.Duration) *http.ServeMux {
	t.Helper()
	store := NewStore(ttl)
	handler := NewHandler(store)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	return mux
}

func TestCreateChallenge(t *testing.T) {
	mux := setupServer(t, DefaultTTL)

	req := httptest.NewRequest("POST", "/challenge", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var c Challenge
	if err := json.NewDecoder(w.Body).Decode(&c); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if c.ID == "" {
		t.Fatal("challenge_id is empty")
	}
	if c.BytesHex == "" || len(c.BytesHex) != 64 {
		t.Fatalf("challenge_bytes should be 64 hex chars, got %d: %s", len(c.BytesHex), c.BytesHex)
	}
	if c.ExpiresAt.IsZero() {
		t.Fatal("expires_at is zero")
	}
}

func TestGetChallenge(t *testing.T) {
	mux := setupServer(t, DefaultTTL)

	// Create a challenge
	req := httptest.NewRequest("POST", "/challenge", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var created Challenge
	json.NewDecoder(w.Body).Decode(&created)

	// Retrieve it
	req = httptest.NewRequest("GET", "/challenge/"+created.ID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var fetched Challenge
	json.NewDecoder(w.Body).Decode(&fetched)
	if fetched.ID != created.ID {
		t.Fatalf("expected ID %s, got %s", created.ID, fetched.ID)
	}
	if fetched.BytesHex != created.BytesHex {
		t.Fatal("challenge_bytes mismatch")
	}
}

func TestGetChallengeNotFound(t *testing.T) {
	mux := setupServer(t, DefaultTTL)

	req := httptest.NewRequest("GET", "/challenge/nonexistent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetChallengeExpired(t *testing.T) {
	mux := setupServer(t, 1*time.Millisecond)

	// Create
	req := httptest.NewRequest("POST", "/challenge", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var created Challenge
	json.NewDecoder(w.Body).Decode(&created)

	// Wait for expiry
	time.Sleep(5 * time.Millisecond)

	// Fetch expired
	req = httptest.NewRequest("GET", "/challenge/"+created.ID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for expired challenge, got %d", w.Code)
	}
}

func TestVerifyMatchingHash(t *testing.T) {
	store := NewStore(DefaultTTL)
	handler := NewHandler(store)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Create challenge
	c, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}

	// Compute correct tbs_hash_bits
	bits := TBSHashBitsFromChallenge(c.Bytes)
	bitsSlice := make([]int, 256)
	copy(bitsSlice, bits[:])

	body, _ := json.Marshal(VerifyRequest{
		ChallengeID: c.ID,
		TBSHashBits: bitsSlice,
		Nullifier:   "test-nullifier",
	})

	req := httptest.NewRequest("POST", "/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp VerifyResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if !resp.Verified {
		t.Fatal("expected verified=true for matching hash")
	}
	if resp.Nullifier != "test-nullifier" {
		t.Fatalf("expected nullifier 'test-nullifier', got '%s'", resp.Nullifier)
	}
}

func TestVerifyWrongHash(t *testing.T) {
	store := NewStore(DefaultTTL)
	handler := NewHandler(store)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	c, _ := store.Create()

	// Send all-zero bits (wrong hash)
	wrongBits := make([]int, 256)
	body, _ := json.Marshal(VerifyRequest{
		ChallengeID: c.ID,
		TBSHashBits: wrongBits,
		Nullifier:   "test",
	})

	req := httptest.NewRequest("POST", "/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp VerifyResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Verified {
		t.Fatal("expected verified=false for wrong hash")
	}
}

func TestVerifyExpiredChallenge(t *testing.T) {
	store := NewStore(1 * time.Millisecond)
	handler := NewHandler(store)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	c, _ := store.Create()
	time.Sleep(5 * time.Millisecond)

	body, _ := json.Marshal(VerifyRequest{
		ChallengeID: c.ID,
		TBSHashBits: make([]int, 256),
		Nullifier:   "test",
	})

	req := httptest.NewRequest("POST", "/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for expired challenge, got %d", w.Code)
	}
}

func TestConcurrentChallengeCreation(t *testing.T) {
	store := NewStore(DefaultTTL)
	var wg sync.WaitGroup
	ids := make(chan string, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := store.Create()
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
			t.Fatalf("duplicate challenge ID: %s", id)
		}
		seen[id] = true
	}
	if len(seen) != 100 {
		t.Fatalf("expected 100 unique challenges, got %d", len(seen))
	}
}

func TestTBSHashBitsFormat(t *testing.T) {
	// Verify our bit conversion matches standard SHA-256
	var challenge [32]byte
	for i := range challenge {
		challenge[i] = byte(i)
	}

	bits := TBSHashBitsFromChallenge(challenge)
	digest := sha256.Sum256(challenge[:])

	// Reconstruct bytes from bits
	for i := 0; i < 32; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			b |= byte(bits[i*8+j]) << (7 - j)
		}
		if b != digest[i] {
			t.Fatalf("byte %d mismatch: got %02x, want %02x", i, b, digest[i])
		}
	}
}
