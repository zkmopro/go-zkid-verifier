// Package fido implements the Taiwan MOI FIDO API (getSpTicket) client.
//
// Checksum algorithm (spec §3.(3)):
//  1. payload  = transaction_id + sp_service_id + id_num + op_code + op_mode + hint + sign_data
//  2. sha256hex = hex( SHA256( payload ) )
//  3. iv        = 12 zero bytes
//  4. ciphertext = AES-256-GCM( key, iv, sha256hex )  [GCM tag appended]
//  5. sp_checksum = hex(iv) + hex(ciphertext+tag)
package fido

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

func init() {
	godotenv.Load() // loads .env if present; silently ignored if missing
}

const baseURL = "https://fidoapi.moi.gov.tw"

func getSpServiceID() string  { return os.Getenv("FIDO_SP_SERVICE_ID") }
func getAESKeyBase64() string { return os.Getenv("FIDO_AES_KEY") }

// SpTicketParams holds all parameters needed to call getSpTicket.
type SpTicketParams struct {
	TransactionID string
	IDNum         string
	OpCode        string // "SIGN" | "ATH" | "NFCSIGN"
	OpMode        string // "APP2APP" | "I-SCAN" | …
	Hint          string
	TimeLimit     string // seconds, e.g. "600"
	SignData      string // base64 string
	SignType      string // "PKCS#7" | "CMS" | "RAW"
	HashAlgorithm string // "SHA256" | …
	TBSEncoding   string // "base64" | "utf8"
}

type signInfo struct {
	TBSEncoding   string `json:"tbs_encoding"`
	SignData      string `json:"sign_data"`
	HashAlgorithm string `json:"hash_algorithm"`
	SignType      string `json:"sign_type"`
}

type getSpTicketRequest struct {
	TransactionID string   `json:"transaction_id"`
	SpServiceID   string   `json:"sp_service_id"`
	SpChecksum    string   `json:"sp_checksum"`
	IDNum         string   `json:"id_num"`
	OpCode        string   `json:"op_code"`
	OpMode        string   `json:"op_mode"`
	Hint          string   `json:"hint"`
	TimeLimit     string   `json:"time_limit"`
	SignInfo      signInfo `json:"sign_info"`
}

// GetSpTicket calls the MOI FIDO getSpTicket endpoint and returns the raw JSON response body.
func GetSpTicket(ctx context.Context, p SpTicketParams) (string, error) {
	payload := p.TransactionID + getSpServiceID() + p.IDNum +
		p.OpCode + p.OpMode + p.Hint + p.SignData

	checksum, err := computeSpChecksum(payload)
	if err != nil {
		return "", fmt.Errorf("compute sp_checksum: %w", err)
	}

	body := getSpTicketRequest{
		TransactionID: p.TransactionID,
		SpServiceID:   getSpServiceID(),
		SpChecksum:    checksum,
		IDNum:         p.IDNum,
		OpCode:        p.OpCode,
		OpMode:        p.OpMode,
		Hint:          p.Hint,
		TimeLimit:     p.TimeLimit,
		SignInfo: signInfo{
			TBSEncoding:   p.TBSEncoding,
			SignData:      p.SignData,
			HashAlgorithm: p.HashAlgorithm,
			SignType:      p.SignType,
		},
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL+"/moise/sp/getSpTicket", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	return string(respBody), nil
}

// ── SP-API-ATH-02: getAthOrSignResult ───────────────────────────────────────

// SpTicketPayload is the JSON embedded inside the base64url sp_ticket string.
// Format: BASE64URL(Payload).BASE64URL(Digest) — only the Payload part is decoded.
type SpTicketPayload struct {
	TransactionID string `json:"transaction_id"`
	SpTicketID    string `json:"sp_ticket_id"`
	OpCode        string `json:"op_code"`
}

// DecodeSpTicket splits "Payload.Digest" on the last dot and base64url-decodes
// the Payload segment into a SpTicketPayload.
func DecodeSpTicket(spTicket string) (*SpTicketPayload, error) {
	// Split on last '.' to isolate the payload segment.
	idx := len(spTicket) - 1
	for idx >= 0 && spTicket[idx] != '.' {
		idx--
	}
	if idx < 0 {
		return nil, fmt.Errorf("sp_ticket missing '.' separator")
	}
	payloadB64 := spTicket[:idx]

	raw, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("decode sp_ticket payload: %w", err)
	}

	var p SpTicketPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("unmarshal sp_ticket payload: %w", err)
	}
	return &p, nil
}

type getAthOrSignResultRequest struct {
	TransactionID string `json:"transaction_id"`
	SpServiceID   string `json:"sp_service_id"`
	SpChecksum    string `json:"sp_checksum"`
	SpTicketID    string `json:"sp_ticket_id"`
}

// SignResult holds the successful result fields (present when ErrorCode == "0").
type SignResult struct {
	HashedIDNum        *string `json:"hashed_id_num,omitempty"`
	SignedResponse     *string `json:"signed_response,omitempty"`
	IdpChecksum        *string `json:"idp_checksum,omitempty"`
	SigningCertificate *string `json:"cert,omitempty"`
}

// AthOrSignResultResponse is the top-level response from getAthOrSignResult.
type AthOrSignResultResponse struct {
	ErrorCode    string      `json:"error_code"`
	ErrorMessage string      `json:"error_message"`
	Result       *SignResult `json:"result,omitempty"`
}

// GetAthOrSignResult queries the MOI FIDO getAthOrSignResult endpoint.
// spTicket is the base64url-encoded JSON string returned by GetSpTicket.
// Per spec, callers should wait at least 4 seconds between poll attempts.
func GetAthOrSignResult(ctx context.Context, spTicket string) (*AthOrSignResultResponse, error) {
	ticket, err := DecodeSpTicket(spTicket)
	if err != nil {
		return nil, fmt.Errorf("decode sp_ticket: %w", err)
	}

	payload := ticket.TransactionID + getSpServiceID() + ticket.SpTicketID
	checksum, err := computeSpChecksum(payload)
	if err != nil {
		return nil, fmt.Errorf("compute sp_checksum: %w", err)
	}

	reqBody := getAthOrSignResultRequest{
		TransactionID: ticket.TransactionID,
		SpServiceID:   getSpServiceID(),
		SpChecksum:    checksum,
		SpTicketID:    ticket.SpTicketID,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL+"/moise/sp/getAthOrSignResult", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var result AthOrSignResultResponse
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return &result, nil
}

// computeSpChecksum implements the 5-step algorithm from the spec.
func computeSpChecksum(payload string) (string, error) {
	// [2] sha256 hex
	sum := sha256.Sum256([]byte(payload))
	sha256hex := hex.EncodeToString(sum[:])

	// [1] decode AES key
	keyBytes, err := base64.StdEncoding.DecodeString(getAESKeyBase64())
	if err != nil {
		return "", fmt.Errorf("decode AES key: %w", err)
	}

	// [3] zero IV (12 bytes)
	iv := make([]byte, 12)

	// [4] AES-256-GCM encrypt
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("aes-gcm: %w", err)
	}
	// Seal appends ciphertext+tag to the destination slice.
	ciphertextWithTag := gcm.Seal(nil, iv, []byte(sha256hex), nil)

	// [5] hex(iv) + hex(ciphertext+tag)
	return hex.EncodeToString(iv) + hex.EncodeToString(ciphertextWithTag), nil
}
