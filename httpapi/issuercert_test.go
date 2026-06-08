package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/privacy-ethereum/go-zkid-verifier/issuercert"
)

func TestIssuerCertStatus_Disabled(t *testing.T) {
	h := NewRouter(nil, nil, nil, nil, testAppID, "")
	req := httptest.NewRequest("GET", "/issuer-cert/status", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if enforced, ok := resp["enforced"].(bool); !ok || enforced {
		t.Errorf("enforced: got %v, want false", resp["enforced"])
	}
}

func TestIssuerCertStatus_Enabled(t *testing.T) {
	p := issuercert.NewStaticProvider(map[issuercert.IssuerID]*issuercert.CertRecord{})
	h := NewRouter(nil, nil, nil, p, testAppID, "")

	req := httptest.NewRequest("GET", "/issuer-cert/status", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if enforced, ok := resp["enforced"].(bool); !ok || !enforced {
		t.Errorf("enforced: got %v, want true", resp["enforced"])
	}
	if _, ok := resp["status"]; !ok {
		t.Error("status key missing")
	}
}
