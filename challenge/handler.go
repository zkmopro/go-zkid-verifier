package challenge

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/zkmopro/go-zkid-verifier/linkverify"
	"github.com/zkmopro/go-zkid-verifier/store"
)

type Handler struct {
	store   store.Store
	keysDir string
}

func NewHandler(s store.Store, keysDir string) *Handler {
	return &Handler{store: s, keysDir: keysDir}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /challenge", h.CreateChallenge)
	mux.HandleFunc("GET /challenge/{id}", h.GetChallenge)
	mux.HandleFunc("POST /verify-tbs", h.VerifyTBSHash)
	mux.HandleFunc("POST /link-verify", h.LinkVerify)
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

// --- TBS hash verification (legacy endpoint) ---

type VerifyTBSRequest struct {
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

func (h *Handler) VerifyTBSHash(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64KB limit
	var req VerifyTBSRequest
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
	err = h.store.VerifyAndRecord(r.Context(), req.Nullifier, req.ChallengeID, nil, "tbs")
	if err != nil {
		writeStoreError(w, err, req.Nullifier)
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

// --- Link-verify (ZK proof verification) ---

type LinkVerifyRequest struct {
	ChallengeID    string `json:"challenge_id"`
	CertChainType  string `json:"cert_chain_type"`  // "rs2048" (default) or "rs4096"
	CertChainProof []byte `json:"cert_chain_proof"`  // base64-encoded in JSON
	DeviceSigProof []byte `json:"device_sig_proof"`  // base64-encoded in JSON
	Nullifier      string `json:"nullifier"`
}

func (h *Handler) LinkVerify(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024) // 2MB limit for proof data
	var req LinkVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if len(req.CertChainProof) == 0 || len(req.DeviceSigProof) == 0 {
		http.Error(w, `{"error":"cert_chain_proof and device_sig_proof are required"}`, http.StatusBadRequest)
		return
	}
	if req.Nullifier == "" {
		http.Error(w, `{"error":"nullifier is required"}`, http.StatusBadRequest)
		return
	}

	// Determine proof type
	pt := linkverify.ProofTypeRS2048
	if req.CertChainType == "rs4096" {
		pt = linkverify.ProofTypeRS4096
	}

	// Look up and validate challenge
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

	// Run ZK link-verify
	verified, err := linkverify.Verify(linkverify.Request{
		CertChainProof: req.CertChainProof,
		DeviceSigProof: req.DeviceSigProof,
		ProofType:      pt,
	}, h.keysDir)
	if err != nil {
		http.Error(w, `{"error":"verification failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	if !verified {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VerifyFailResponse{
			Verified:  false,
			Nullifier: req.Nullifier,
		})
		return
	}

	// Atomically: record verification + consume challenge
	proofType := "link_rs2048"
	if pt == linkverify.ProofTypeRS4096 {
		proofType = "link_rs4096"
	}
	err = h.store.VerifyAndRecord(r.Context(), req.Nullifier, req.ChallengeID, nil, proofType)
	if err != nil {
		writeStoreError(w, err, req.Nullifier)
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

// writeStoreError maps store sentinel errors to HTTP responses.
func writeStoreError(w http.ResponseWriter, err error, nullifier string) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case errors.Is(err, store.ErrDuplicateNullifier):
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"error":     "nullifier already registered",
			"nullifier": nullifier,
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
}
