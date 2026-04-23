package httpapi

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/zkmopro/go-zkid-verifier/store"
)

func createChallenge(s store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := s.CreateChallenge(r.Context())
		if err != nil {
			jsonError(w, "failed to create challenge", http.StatusInternalServerError)
			return
		}
		log.Printf("challenge id: %s", c.ID)
		log.Printf("created challenge: %s", c.BytesHex)
		log.Printf("challenge expires at: %v", c.ExpiresAt)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c)
	}
}

func getChallenge(s store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		c, err := s.GetChallenge(r.Context(), id)
		if err != nil {
			log.Printf("get challenge error: %v", err)
			jsonError(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if c == nil {
			jsonError(w, "challenge not found", http.StatusNotFound)
			return
		}
		if time.Now().After(c.ExpiresAt) {
			jsonError(w, "challenge expired", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c)
	}
}
