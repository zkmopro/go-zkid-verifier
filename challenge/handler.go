package challenge

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/zkmopro/go-zkid-verifier/store"
)

type Handler struct {
	store store.Store
}

func NewHandler(s store.Store) *Handler {
	return &Handler{store: s}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /challenge", h.CreateChallenge)
	mux.HandleFunc("GET /challenge/{id}", h.GetChallenge)
	mux.HandleFunc("POST /verify", h.VerifyProof)
	mux.HandleFunc("GET /users/{nullifier}/status", h.GetVerificationStatus)
}

func (h *Handler) CreateChallenge(w http.ResponseWriter, r *http.Request) {
	c, err := h.store.CreateChallenge(r.Context())
	if err != nil {
		http.Error(w, `{"error":"failed to create challenge"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(c)
}

func (h *Handler) GetChallenge(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	c, err := h.store.GetChallenge(r.Context(), id)
	if err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}
	if c == nil {
		http.Error(w, `{"error":"challenge not found"}`, http.StatusNotFound)
		return
	}
	if time.Now().After(c.ExpiresAt) {
		http.Error(w, `{"error":"challenge expired"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(c)
}

type VerifyRequest struct {
	ChallengeID string `json:"challenge_id"`
	TBSHashBits []int  `json:"tbs_hash_bits"`
	Nullifier   string `json:"nullifier"`
}

type VerifySuccessResponse struct {
	Verified   bool   `json:"verified"`
	Nullifier  string `json:"nullifier"`
	IDVerified bool   `json:"id_verified,omitempty"`
	Persisted  bool   `json:"persisted,omitempty"`
}

type VerifyFailResponse struct {
	Verified  bool   `json:"verified"`
	Nullifier string `json:"nullifier"`
}

func (h *Handler) VerifyProof(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64KB limit
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Look up challenge (non-authoritative fast-fail for expiry)
	c, err := h.store.GetChallenge(r.Context(), req.ChallengeID)
	if err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}
	if c == nil {
		http.Error(w, `{"error":"challenge not found or expired"}`, http.StatusNotFound)
		return
	}
	if time.Now().After(c.ExpiresAt) {
		http.Error(w, `{"error":"challenge expired"}`, http.StatusBadRequest)
		return
	}

	// Verify tbs_hash matches SHA256(challenge_bytes)
	verified := VerifyTBSHash(c.Bytes, req.TBSHashBits)
	if !verified {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VerifyFailResponse{
			Verified:  false,
			Nullifier: req.Nullifier,
		})
		return
	}

	// Atomically: record verification + consume challenge (inside TX)
	err = h.store.VerifyAndRecord(r.Context(), req.Nullifier, req.ChallengeID, nil)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case errors.Is(err, store.ErrDuplicateNullifier):
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error":     "nullifier already registered",
				"nullifier": req.Nullifier,
			})
		case errors.Is(err, store.ErrChallengeNotFound):
			http.Error(w, `{"error":"challenge not found"}`, http.StatusNotFound)
		case errors.Is(err, store.ErrChallengeExpired):
			http.Error(w, `{"error":"challenge expired"}`, http.StatusBadRequest)
		case errors.Is(err, store.ErrChallengeConsumed):
			http.Error(w, `{"error":"challenge already consumed"}`, http.StatusGone)
		default:
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(VerifySuccessResponse{
		Verified:   true,
		Nullifier:  req.Nullifier,
		IDVerified: true,
		Persisted:  true,
	})
}

func (h *Handler) GetVerificationStatus(w http.ResponseWriter, r *http.Request) {
	nullifier := r.PathValue("nullifier")
	if nullifier == "" {
		http.Error(w, `{"error":"nullifier required"}`, http.StatusBadRequest)
		return
	}

	rec, err := h.store.GetVerification(r.Context(), nullifier)
	if err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}
	if rec == nil {
		http.Error(w, `{"error":"nullifier not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rec)
}
