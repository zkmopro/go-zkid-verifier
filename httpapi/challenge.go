package httpapi

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/zkmopro/go-zkid-verifier/store"
)

type ChallengeResponse struct {
	Challenge string    `json:"challenge"`
	AppID     string    `json:"app_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func createChallenge(s store.Store, appID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := s.CreateChallenge(r.Context())
		if err != nil {
			jsonError(w, "failed to create challenge", http.StatusInternalServerError)
			return
		}
		log.Printf("issued challenge=%s expires_at=%v", c.Challenge, c.ExpiresAt)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ChallengeResponse{
			Challenge: c.Challenge,
			AppID:     appID,
			ExpiresAt: c.ExpiresAt,
		})
	}
}

func getChallenge(s store.Store, appID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		challenge := r.PathValue("challenge")

		c, err := s.GetChallenge(r.Context(), challenge)
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
		json.NewEncoder(w).Encode(ChallengeResponse{
			Challenge: c.Challenge,
			AppID:     appID,
			ExpiresAt: c.ExpiresAt,
		})
	}
}
