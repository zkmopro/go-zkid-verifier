package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zkmopro/go-zkid-verifier/store"
)

const testAppID = "11111111111111111111111111111111111111111111111111111111111111"

func setupServer(t *testing.T, ttl time.Duration) (http.Handler, *store.SQLiteStore) {
	t.Helper()
	s, err := store.NewSQLiteStore(":memory:", ttl)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return NewRouter(nil, s, nil, nil, testAppID, ""), s
}

func createChallengeViaHTTP(t *testing.T, mux http.Handler) ChallengeResponse {
	t.Helper()
	req := httptest.NewRequest("POST", "/challenge", strings.NewReader(""))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create challenge: %d %s", w.Code, w.Body.String())
	}
	var c ChallengeResponse
	json.NewDecoder(w.Body).Decode(&c)
	return c
}
