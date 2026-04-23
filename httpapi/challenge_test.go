package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zkmopro/go-zkid-verifier/challenge"
	"github.com/zkmopro/go-zkid-verifier/store"
)

func TestCreateChallenge(t *testing.T) {
	mux, _ := setupServer(t, challenge.DefaultTTL)
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
	mux, _ := setupServer(t, challenge.DefaultTTL)
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
	mux, _ := setupServer(t, challenge.DefaultTTL)

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
