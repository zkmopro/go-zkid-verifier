package httpapi

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/zkmopro/go-zkid-verifier/linkverify"
	"github.com/zkmopro/go-zkid-verifier/store"
)

func linkVerify(service *linkverify.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)
		var req LinkVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if req.Challenge == "" {
			jsonError(w, "challenge is required", http.StatusBadRequest)
			return
		}
		if len(req.CertChainProof) == 0 || len(req.DeviceSigProof) == 0 {
			jsonError(w, "cert_chain_proof and device_sig_proof are required", http.StatusBadRequest)
			return
		}

		pt, err := linkverify.ParseProofType(req.CertChainType)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}

		result, err := service.VerifyAndRecord(r.Context(), req.Challenge, linkverify.Request{
			CertChainProof: req.CertChainProof,
			DeviceSigProof: req.DeviceSigProof,
			ProofType:      pt,
		})
		if err != nil {
			switch {
			case errors.Is(err, store.ErrChallengeNotFound):
				jsonError(w, "challenge not found or already consumed", http.StatusNotFound)
			case errors.Is(err, linkverify.ErrSmtRootUnavailable):
				log.Printf("link-verify smt root unavailable: %v", err)
				jsonError(w, "smt root provider unavailable, retry later", http.StatusServiceUnavailable)
			case errors.Is(err, linkverify.ErrIssuerCertUnavailable):
				log.Printf("link-verify issuer cert unavailable: %v", err)
				jsonError(w, "issuer cert provider unavailable, retry later", http.StatusServiceUnavailable)
			case errors.Is(err, store.ErrChallengeExpired),
				errors.Is(err, store.ErrChallengeConsumed),
				errors.Is(err, store.ErrDuplicateNullifier):
				nullifier := ""
				if result != nil {
					nullifier = result.Nullifier
				}
				writeStoreError(w, err, nullifier)
			default:
				log.Printf("link-verify error: %v", err)
				jsonError(w, "proof verification failed", http.StatusInternalServerError)
			}
			return
		}
		if !result.Verified {
			status := http.StatusOK
			switch result.Reason {
			case linkverify.ReasonSmtRootMismatch,
				linkverify.ReasonIssuerModulusMismatch,
				linkverify.ReasonAppIDMismatch,
				linkverify.ReasonChallengeMismatch:
				status = http.StatusConflict
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(VerifyFailResponse{
				Verified:      false,
				Reason:        result.Reason,
				SmtRoot:       result.SmtRoot,
				IssuerModulus: result.IssuerModulus,
				AppID:         result.AppID,
				Challenge:     result.Challenge,
			})
			return
		}
		parsed := result.Parsed
		log.Printf("link-verify parsed inputs: challenge=%s pk_commit=%s nullifier=%s app_id=%s smt_root=%s",
			parsed.Challenge, parsed.PkCommit, parsed.Nullifier, parsed.AppID, parsed.SmtRoot)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VerifySuccessResponse{
			Verified:      true,
			Nullifier:     result.Nullifier,
			IDVerified:    true,
			Persisted:     true,
			PublicSignals: result.Signals,
			ParsedInputs:  result.Parsed,
			SmtRoot:       result.SmtRoot,
			IssuerModulus: result.IssuerModulus,
			AppID:         result.AppID,
			Challenge:     result.Challenge,
		})
	}
}
