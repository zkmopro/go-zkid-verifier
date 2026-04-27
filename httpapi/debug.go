package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/zkmopro/go-zkid-verifier/store"
)

// cleanDB returns a handler that wipes the challenges and verifications tables.
// The route is only registered when DEBUG_TOKEN is set (see NewRouter), so
// token here is guaranteed non-empty at call time.
func cleanDB(s store.Store, token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validDebugToken(r, token) {
			jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		nc, nv, err := s.CleanDB(r.Context())
		if err != nil {
			log.Printf("debug clean-db: %v", err)
			jsonError(w, "internal server error", http.StatusInternalServerError)
			return
		}
		log.Printf("debug clean-db ok: challenges=%d verifications=%d", nc, nv)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int64{
			"challenges_deleted":    nc,
			"verifications_deleted": nv,
		})
	}
}

func validDebugToken(r *http.Request, want string) bool {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	got := h[len(prefix):]
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
