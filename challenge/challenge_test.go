package challenge

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zkmopro/go-zkid-verifier/store"
)

func setupServer(t *testing.T, ttl time.Duration) (*http.ServeMux, *store.SQLiteStore) {
	t.Helper()
	s, err := store.NewSQLiteStore(":memory:", ttl)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	handler := NewHandler(s)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	return mux, s
}

func createChallengeViaHTTP(t *testing.T, mux *http.ServeMux) store.Challenge {
	t.Helper()
	req := httptest.NewRequest("POST", "/challenge", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create challenge: %d %s", w.Code, w.Body.String())
	}
	var c store.Challenge
	json.NewDecoder(w.Body).Decode(&c)
	return c
}

func verifyViaHTTP(t *testing.T, mux *http.ServeMux, challengeID string, bits []int, nullifier string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(VerifyRequest{
		ChallengeID: challengeID,
		TBSHashBits: bits,
		Nullifier:   nullifier,
	})
	req := httptest.NewRequest("POST", "/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func correctBits(c store.Challenge) []int {
	bits := TBSHashBitsFromChallenge(c.Bytes)
	slice := make([]int, 256)
	copy(slice, bits[:])
	return slice
}

// --- Challenge endpoint tests ---

func TestCreateChallenge(t *testing.T) {
	mux, _ := setupServer(t, DefaultTTL)
	c := createChallengeViaHTTP(t, mux)

	if c.ID == "" {
		t.Fatal("challenge_id is empty")
	}
	if c.BytesHex == "" || len(c.BytesHex) != 31 {
		t.Fatalf("challenge_bytes should be 31 hex chars, got %d: %s", len(c.BytesHex), c.BytesHex)
	}
	if c.ExpiresAt.IsZero() {
		t.Fatal("expires_at is zero")
	}
}

func TestGetChallenge(t *testing.T) {
	mux, _ := setupServer(t, DefaultTTL)
	created := createChallengeViaHTTP(t, mux)

	req := httptest.NewRequest("GET", "/challenge/"+created.ID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var fetched store.Challenge
	json.NewDecoder(w.Body).Decode(&fetched)
	if fetched.ID != created.ID {
		t.Fatalf("expected ID %s, got %s", created.ID, fetched.ID)
	}
	if fetched.BytesHex != created.BytesHex {
		t.Fatal("challenge_bytes mismatch")
	}
}

func TestGetChallengeNotFound(t *testing.T) {
	mux, _ := setupServer(t, DefaultTTL)

	req := httptest.NewRequest("GET", "/challenge/nonexistent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetChallengeExpired(t *testing.T) {
	mux, _ := setupServer(t, 1*time.Millisecond)
	created := createChallengeViaHTTP(t, mux)
	time.Sleep(5 * time.Millisecond)

	req := httptest.NewRequest("GET", "/challenge/"+created.ID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for expired challenge, got %d", w.Code)
	}
}

// --- Verify endpoint tests ---

func TestVerifyMatchingHash(t *testing.T) {
	mux, s := setupServer(t, DefaultTTL)
	c, _ := s.CreateChallenge(t.Context())

	w := verifyViaHTTP(t, mux, c.ID, correctBits(*c), "test-nullifier")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp VerifySuccessResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if !resp.Verified {
		t.Fatal("expected verified=true")
	}
	if !resp.IDVerified {
		t.Fatal("expected id_verified=true")
	}
	if !resp.Persisted {
		t.Fatal("expected persisted=true")
	}
}

func TestVerifyMatchingHashPersists(t *testing.T) {
	mux, s := setupServer(t, DefaultTTL)
	c, _ := s.CreateChallenge(t.Context())

	verifyViaHTTP(t, mux, c.ID, correctBits(*c), "persist-test")

	rec, err := s.GetVerification(t.Context(), "persist-test")
	if err != nil {
		t.Fatalf("get verification: %v", err)
	}
	if rec == nil {
		t.Fatal("verification not persisted")
	}
	if !rec.IDVerified {
		t.Fatal("expected id_verified=true")
	}
}

func TestVerifyWrongHash(t *testing.T) {
	mux, s := setupServer(t, DefaultTTL)
	c, _ := s.CreateChallenge(t.Context())

	wrongBits := make([]int, 256)
	w := verifyViaHTTP(t, mux, c.ID, wrongBits, "test")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp VerifyFailResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Verified {
		t.Fatal("expected verified=false")
	}

	// Nothing should be persisted
	rec, _ := s.GetVerification(t.Context(), "test")
	if rec != nil {
		t.Fatal("failed verification should not be persisted")
	}
}

func TestVerifyDuplicateNullifier409(t *testing.T) {
	mux, s := setupServer(t, DefaultTTL)
	c1, _ := s.CreateChallenge(t.Context())
	c2, _ := s.CreateChallenge(t.Context())

	// First verify succeeds
	w := verifyViaHTTP(t, mux, c1.ID, correctBits(*c1), "dupe-null")
	if w.Code != http.StatusOK {
		t.Fatalf("first verify: %d %s", w.Code, w.Body.String())
	}

	// Second with same nullifier returns 409
	w = verifyViaHTTP(t, mux, c2.ID, correctBits(*c2), "dupe-null")
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestVerifyChallengeConsumed410(t *testing.T) {
	mux, s := setupServer(t, DefaultTTL)
	c, _ := s.CreateChallenge(t.Context())

	// First verify consumes challenge
	verifyViaHTTP(t, mux, c.ID, correctBits(*c), "first")

	// Second attempt on same challenge returns 410
	w := verifyViaHTTP(t, mux, c.ID, correctBits(*c), "second")
	if w.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d: %s", w.Code, w.Body.String())
	}
}

func TestVerifyExpiredChallenge(t *testing.T) {
	mux, s := setupServer(t, 1*time.Millisecond)
	c, _ := s.CreateChallenge(t.Context())
	time.Sleep(5 * time.Millisecond)

	w := verifyViaHTTP(t, mux, c.ID, make([]int, 256), "test")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for expired challenge, got %d", w.Code)
	}
}

func TestVerifyInvalidBody(t *testing.T) {
	mux, _ := setupServer(t, DefaultTTL)

	req := httptest.NewRequest("POST", "/verify", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestVerifyNonexistentChallenge(t *testing.T) {
	mux, _ := setupServer(t, DefaultTTL)

	w := verifyViaHTTP(t, mux, "nonexistent", make([]int, 256), "test")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// --- Status endpoint tests ---

func TestGetVerificationStatusFound(t *testing.T) {
	mux, s := setupServer(t, DefaultTTL)
	c, _ := s.CreateChallenge(t.Context())
	verifyViaHTTP(t, mux, c.ID, correctBits(*c), "status-test")

	req := httptest.NewRequest("GET", "/users/status-test/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var rec store.VerificationRecord
	json.NewDecoder(w.Body).Decode(&rec)
	if rec.Nullifier != "status-test" {
		t.Fatalf("nullifier: got %s, want status-test", rec.Nullifier)
	}
	if !rec.IDVerified {
		t.Fatal("expected id_verified=true")
	}
}

func TestGetVerificationStatusNotFound(t *testing.T) {
	mux, _ := setupServer(t, DefaultTTL)

	req := httptest.NewRequest("GET", "/users/nonexistent/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// --- Integration: full demo flow ---

func TestFullDemoFlow(t *testing.T) {
	mux, s := setupServer(t, DefaultTTL)

	// 1. Create challenge
	c, _ := s.CreateChallenge(t.Context())

	// 2. Verify with correct hash
	w := verifyViaHTTP(t, mux, c.ID, correctBits(*c), "demo-nullifier")
	if w.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", w.Code, w.Body.String())
	}

	// 3. Query status
	req := httptest.NewRequest("GET", "/users/demo-nullifier/status", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}

	// 4. Try same nullifier again — 409
	c2, _ := s.CreateChallenge(t.Context())
	w = verifyViaHTTP(t, mux, c2.ID, correctBits(*c2), "demo-nullifier")
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

// --- TBS hash utility (preserved from original) ---

func TestTBSHashBitsFormat(t *testing.T) {
	var challenge [16]byte
	for i := range challenge {
		challenge[i] = byte(i)
	}

	bits := TBSHashBitsFromChallenge(challenge)
	digest := sha256.Sum256(challenge[:])

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
