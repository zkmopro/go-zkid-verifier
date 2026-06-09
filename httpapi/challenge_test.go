package httpapi

import (
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/privacy-ethereum/go-zkid-verifier/challenge"
)

func TestCreateChallenge(t *testing.T) {
	mux, _ := setupServer(t, challenge.DefaultTTL)
	c := createChallengeViaHTTP(t, mux)

	if c.Challenge == "" {
		t.Fatal("challenge is empty")
	}
	if c.AppID != testAppID {
		t.Fatalf("app_id: got %q, want %q", c.AppID, testAppID)
	}
	if c.ExpiresAt.IsZero() {
		t.Fatal("expires_at is zero")
	}
	// The challenge field is what binds the proof to this session.
	if c.Challenge == "" {
		t.Fatal("challenge is empty")
	}
	if _, ok := new(big.Int).SetString(c.Challenge, 10); !ok {
		t.Fatalf("challenge is not a decimal field element: %q", c.Challenge)
	}
}

func TestGetChallenge(t *testing.T) {
	mux, _ := setupServer(t, challenge.DefaultTTL)
	created := createChallengeViaHTTP(t, mux)

	req := httptest.NewRequest("GET", "/challenge/"+created.Challenge, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var fetched ChallengeResponse
	json.NewDecoder(w.Body).Decode(&fetched)
	if fetched.Challenge != created.Challenge {
		t.Fatalf("expected challenge %s, got %s", created.Challenge, fetched.Challenge)
	}
	if fetched.AppID != created.AppID {
		t.Fatal("app_id mismatch")
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

	req := httptest.NewRequest("GET", "/challenge/"+created.Challenge, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for expired challenge, got %d", w.Code)
	}
}
