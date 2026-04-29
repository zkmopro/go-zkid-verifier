package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zkmopro/go-zkid-verifier/challenge"
)

func TestCreateChallenge(t *testing.T) {
	mux, _ := setupServer(t, challenge.DefaultTTL)
	c := createChallengeViaHTTP(t, mux)

	if c.ChallengeID == "" {
		t.Fatal("challenge_id is empty")
	}
	if c.AppID != testAppID {
		t.Fatalf("app_id: got %q, want %q", c.AppID, testAppID)
	}
	if c.ExpiresAt.IsZero() {
		t.Fatal("expires_at is zero")
	}
}

func TestGetChallenge(t *testing.T) {
	mux, _ := setupServer(t, challenge.DefaultTTL)
	created := createChallengeViaHTTP(t, mux)

	req := httptest.NewRequest("GET", "/challenge/"+created.ChallengeID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var fetched ChallengeResponse
	json.NewDecoder(w.Body).Decode(&fetched)
	if fetched.ChallengeID != created.ChallengeID {
		t.Fatalf("expected ID %s, got %s", created.ChallengeID, fetched.ChallengeID)
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

	req := httptest.NewRequest("GET", "/challenge/"+created.ChallengeID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for expired challenge, got %d", w.Code)
	}
}
