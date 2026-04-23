package httpapi

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/zkmopro/go-zkid-verifier/store"
)

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeStoreError(w http.ResponseWriter, err error, nullifier string) {
	switch {
	case errors.Is(err, store.ErrDuplicateNullifier):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"error":     "nullifier already registered",
			"nullifier": nullifier,
		})
	case errors.Is(err, store.ErrChallengeNotFound):
		jsonError(w, "challenge not found", http.StatusNotFound)
	case errors.Is(err, store.ErrChallengeExpired):
		jsonError(w, "challenge expired", http.StatusBadRequest)
	case errors.Is(err, store.ErrChallengeConsumed):
		jsonError(w, "challenge already consumed", http.StatusGone)
	default:
		log.Printf("store error for nullifier %s: %v", nullifier, err)
		jsonError(w, "internal server error", http.StatusInternalServerError)
	}
}
