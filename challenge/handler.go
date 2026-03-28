package challenge

import (
	"encoding/json"
	"net/http"
	"strings"
)

type Handler struct {
	store *Store
}

func NewHandler(store *Store) *Handler {
	return &Handler{store: store}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /challenge", h.CreateChallenge)
	mux.HandleFunc("GET /challenge/{id}", h.GetChallenge)
	mux.HandleFunc("POST /verify", h.VerifyProof)
}

func (h *Handler) CreateChallenge(w http.ResponseWriter, r *http.Request) {
	c, err := h.store.Create()
	if err != nil {
		http.Error(w, `{"error":"failed to create challenge"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(c)
}

func (h *Handler) GetChallenge(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		id = lastPathSegment(r.URL.Path)
	}

	c, ok := h.store.Get(id)
	if !ok {
		http.Error(w, `{"error":"challenge not found or expired"}`, http.StatusNotFound)
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

type VerifyResponse struct {
	Verified  bool   `json:"verified"`
	Nullifier string `json:"nullifier"`
}

func (h *Handler) VerifyProof(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	c, ok := h.store.Get(req.ChallengeID)
	if !ok {
		http.Error(w, `{"error":"challenge not found or expired"}`, http.StatusNotFound)
		return
	}

	verified := VerifyTBSHash(c.Bytes, req.TBSHashBits)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(VerifyResponse{
		Verified:  verified,
		Nullifier: req.Nullifier,
	})
}

func lastPathSegment(path string) string {
	path = strings.TrimRight(path, "/")
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		return path[idx+1:]
	}
	return path
}
