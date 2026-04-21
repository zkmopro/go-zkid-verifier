package challenge

import (
	"encoding/json"
	"errors"
	"log"
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
		jsonError(w, "failed to create challenge", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(c)
}

func (h *Handler) GetChallenge(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	c, err := h.store.GetChallenge(r.Context(), id)
	if err != nil {
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

// --- TBS hash verification (legacy endpoint) ---

type VerifyTBSRequest struct {
	ChallengeID string `json:"challenge_id"`
	TBSHashBits []int  `json:"tbs_hash_bits"`
	Nullifier   string `json:"nullifier"`
}

type VerifySuccessResponse struct {
	Verified      bool                    `json:"verified"`
	Nullifier     string                  `json:"nullifier"`
	IDVerified    bool                    `json:"id_verified,omitempty"`
	Persisted     bool                    `json:"persisted,omitempty"`
	PublicSignals *linkverify.PublicSignals `json:"public_signals,omitempty"`
}

type VerifyFailResponse struct {
	Verified  bool   `json:"verified"`
	Nullifier string `json:"nullifier"`
}

func (h *Handler) VerifyTBSHash(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64KB limit
	var req VerifyTBSRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.ChallengeID == "" || req.Nullifier == "" {
		jsonError(w, "challenge_id and nullifier are required", http.StatusBadRequest)
		return
	}

	// Look up challenge (non-authoritative fast-fail for expiry)
	c, err := h.store.GetChallenge(r.Context(), req.ChallengeID)
	if err != nil {
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if c == nil {
		jsonError(w, "challenge not found or expired", http.StatusNotFound)
		return
	}
	if time.Now().After(c.ExpiresAt) {
		jsonError(w, "challenge expired", http.StatusBadRequest)
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
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.ChallengeID == "" {
		jsonError(w, "challenge_id is required", http.StatusBadRequest)
		return
	}
	if len(req.CertChainProof) == 0 || len(req.DeviceSigProof) == 0 {
		jsonError(w, "cert_chain_proof and device_sig_proof are required", http.StatusBadRequest)
		return
	}
	if req.Nullifier == "" {
		jsonError(w, "nullifier is required", http.StatusBadRequest)
		return
	}

	// Validate and determine proof type
	pt, err := parseCertChainType(req.CertChainType)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Look up and validate challenge
	c, err := h.store.GetChallenge(r.Context(), req.ChallengeID)
	if err != nil {
		log.Printf("link-verify get challenge error: %v", err)
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if c == nil {
		jsonError(w, "challenge not found or expired", http.StatusNotFound)
		return
	}
	if time.Now().After(c.ExpiresAt) {
		jsonError(w, "challenge expired", http.StatusBadRequest)
		return
	}

	// Run ZK link-verify
	verified, signals, err := linkverify.Verify(linkverify.Request{
		CertChainProof: req.CertChainProof,
		DeviceSigProof: req.DeviceSigProof,
		ProofType:      pt,
	}, h.keysDir)
	if err != nil {
		log.Printf("link-verify error: %v", err)
		jsonError(w, "proof verification failed", http.StatusInternalServerError)
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
		Verified:      true,
		Nullifier:     req.Nullifier,
		IDVerified:    true,
		Persisted:     true,
		PublicSignals: signals,
	})
}

func (h *Handler) GetVerificationStatus(w http.ResponseWriter, r *http.Request) {
	nullifier := r.PathValue("nullifier")
	if nullifier == "" {
		jsonError(w, "nullifier required", http.StatusBadRequest)
		return
	}

	rec, err := h.store.GetVerification(r.Context(), nullifier)
	if err != nil {
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if rec == nil {
		jsonError(w, "nullifier not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rec)
}

// parseCertChainType validates the cert_chain_type field.
func parseCertChainType(s string) (linkverify.ProofType, error) {
	switch s {
	case "", "rs2048":
		return linkverify.ProofTypeRS2048, nil
	case "rs4096":
		return linkverify.ProofTypeRS4096, nil
	default:
		return "", errors.New("invalid cert_chain_type: must be rs2048 or rs4096")
	}
}

// jsonError writes a JSON error response with the correct Content-Type.
func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// writeStoreError maps store sentinel errors to JSON HTTP responses.
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
