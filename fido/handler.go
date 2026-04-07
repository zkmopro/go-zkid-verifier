package fido

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

// Handler exposes FIDO API endpoints over HTTP.
type Handler struct{}

func NewHandler() *Handler { return &Handler{} }

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /fido/sp-ticket", h.GetSpTicketHandler)
	mux.HandleFunc("POST /fido/ath-result", h.GetAthOrSignResultHandler)
}

// SpTicketRequest is the JSON body accepted by POST /fido/sp-ticket.
// Only id_num is required; all other fields have sensible defaults.
type SpTicketRequest struct {
	IDNum         string `json:"id_num"`
	TransactionID string `json:"transaction_id,omitempty"`
	OpCode        string `json:"op_code,omitempty"`
	OpMode        string `json:"op_mode,omitempty"`
	Hint          string `json:"hint,omitempty"`
	TimeLimit     string `json:"time_limit,omitempty"`
	SignData      string `json:"sign_data,omitempty"`
	SignType      string `json:"sign_type,omitempty"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
	TBSEncoding   string `json:"tbs_encoding,omitempty"`
}

// AthResultRequest is the JSON body accepted by POST /fido/ath-result.
type AthResultRequest struct {
	SpTicket string `json:"sp_ticket"`
}

func (h *Handler) GetAthOrSignResultHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

	var req AthResultRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.SpTicket == "" {
		http.Error(w, `{"error":"sp_ticket is required"}`, http.StatusBadRequest)
		return
	}

	result, err := GetAthOrSignResult(r.Context(), req.SpTicket)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) GetSpTicketHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

	var req SpTicketRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.IDNum == "" {
		http.Error(w, `{"error":"id_num is required"}`, http.StatusBadRequest)
		return
	}

	// Apply defaults
	if req.TransactionID == "" {
		req.TransactionID = uuid.NewString()
	}
	if req.OpCode == "" {
		req.OpCode = "SIGN"
	}
	if req.OpMode == "" {
		req.OpMode = "APP2APP"
	}
	if req.TimeLimit == "" {
		req.TimeLimit = "600"
	}
	if req.SignType == "" {
		req.SignType = "PKCS#7"
	}
	if req.HashAlgorithm == "" {
		req.HashAlgorithm = "SHA256"
	}
	if req.TBSEncoding == "" {
		req.TBSEncoding = "base64"
	}
	if req.SignData == "" {
		req.SignData = "RE9DX0RJR0VTVF8xMjM0NTY3ODkw"
	}

	result, err := GetSpTicket(r.Context(), SpTicketParams{
		TransactionID: req.TransactionID,
		IDNum:         req.IDNum,
		OpCode:        req.OpCode,
		OpMode:        req.OpMode,
		Hint:          req.Hint,
		TimeLimit:     req.TimeLimit,
		SignData:      req.SignData,
		SignType:      req.SignType,
		HashAlgorithm: req.HashAlgorithm,
		TBSEncoding:   req.TBSEncoding,
	})
	if err != nil {
		http.Error(w, `{"error":"fido api error: `+err.Error()+`"}`, http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(result))
}
