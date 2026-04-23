package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zkmopro/go-zkid-verifier/store"
)

func TestWriteStoreErrorStatusCodes(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"duplicate nullifier → 409", store.ErrDuplicateNullifier, http.StatusConflict},
		{"challenge not found → 404", store.ErrChallengeNotFound, http.StatusNotFound},
		{"challenge expired → 400", store.ErrChallengeExpired, http.StatusBadRequest},
		{"challenge consumed → 410", store.ErrChallengeConsumed, http.StatusGone},
		{"unknown error → 500", errors.New("boom"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeStoreError(w, c.err, "n1")
			if w.Code != c.want {
				t.Fatalf("status: got %d, want %d; body=%s", w.Code, c.want, w.Body.String())
			}
			if ct := w.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type: got %q, want application/json", ct)
			}
		})
	}
}
