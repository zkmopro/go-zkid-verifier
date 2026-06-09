package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/privacy-ethereum/go-zkid-verifier/store"
)

const debugTestToken = "test-debug-token-32bytes-of-secret"

func setupDebugServer(t *testing.T, token string) (http.Handler, *store.SQLiteStore) {
	t.Helper()
	s, err := store.NewSQLiteStore(":memory:", 5*time.Minute)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return NewRouter(nil, s, nil, nil, testAppID, token), s
}

func seedOne(t *testing.T, s *store.SQLiteStore) {
	t.Helper()
	ctx := context.Background()
	c, err := s.CreateChallenge(ctx)
	if err != nil {
		t.Fatalf("seed challenge: %v", err)
	}
	if err := s.VerifyAndRecord(ctx, "seed-nullifier", c.Challenge, nil, "link_rs2048"); err != nil {
		t.Fatalf("seed verify: %v", err)
	}
}

func TestCleanDB_RouteAbsentWhenTokenUnset(t *testing.T) {
	mux, _ := setupDebugServer(t, "")

	req := httptest.NewRequest(http.MethodPost, "/debug/db/clean", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404", w.Code)
	}
}

func TestCleanDB_MissingAuthHeader(t *testing.T) {
	mux, s := setupDebugServer(t, debugTestToken)
	seedOne(t, s)

	req := httptest.NewRequest(http.MethodPost, "/debug/db/clean", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", w.Code)
	}

	// DB must be untouched.
	c, _ := s.CreateChallenge(context.Background())
	if c == nil {
		t.Fatal("DB no longer functional")
	}
}

func TestCleanDB_WrongBearerToken(t *testing.T) {
	mux, s := setupDebugServer(t, debugTestToken)
	seedOne(t, s)

	req := httptest.NewRequest(http.MethodPost, "/debug/db/clean", nil)
	req.Header.Set("Authorization", "Bearer not-the-right-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", w.Code)
	}
}

func TestCleanDB_NonBearerScheme(t *testing.T) {
	mux, _ := setupDebugServer(t, debugTestToken)

	req := httptest.NewRequest(http.MethodPost, "/debug/db/clean", nil)
	req.Header.Set("Authorization", "Basic "+debugTestToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", w.Code)
	}
}

func TestCleanDB_HappyPath(t *testing.T) {
	mux, s := setupDebugServer(t, debugTestToken)
	seedOne(t, s)

	req := httptest.NewRequest(http.MethodPost, "/debug/db/clean", nil)
	req.Header.Set("Authorization", "Bearer "+debugTestToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, body %s", w.Code, w.Body.String())
	}

	var body map[string]int64
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["challenges_deleted"] != 1 {
		t.Fatalf("challenges_deleted: got %d, want 1", body["challenges_deleted"])
	}
	if body["verifications_deleted"] != 1 {
		t.Fatalf("verifications_deleted: got %d, want 1", body["verifications_deleted"])
	}

	// Second call on an empty DB returns zeros.
	req2 := httptest.NewRequest(http.MethodPost, "/debug/db/clean", nil)
	req2.Header.Set("Authorization", "Bearer "+debugTestToken)
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("idempotent call status: got %d, body %s", w2.Code, w2.Body.String())
	}
	var body2 map[string]int64
	if err := json.NewDecoder(w2.Body).Decode(&body2); err != nil {
		t.Fatalf("decode body2: %v", err)
	}
	if body2["challenges_deleted"] != 0 || body2["verifications_deleted"] != 0 {
		t.Fatalf("idempotent counts: got %+v, want zeros", body2)
	}
}

func TestCleanDB_WrongMethod(t *testing.T) {
	mux, _ := setupDebugServer(t, debugTestToken)

	req := httptest.NewRequest(http.MethodGet, "/debug/db/clean", nil)
	req.Header.Set("Authorization", "Bearer "+debugTestToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d, want 405", w.Code)
	}
}
