package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/zkmopro/go-zkid-verifier/issuercert"
)

func issuerCertStatus(provider *issuercert.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if provider == nil {
			json.NewEncoder(w).Encode(map[string]any{"enforced": false})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"enforced": true,
			"status":   provider.Status(),
		})
	}
}
