package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/zkmopro/go-zkid-verifier/smtroot"
)

func smtRootStatus(provider *smtroot.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if provider == nil {
			json.NewEncoder(w).Encode(map[string]any{"enforced": false})
			return
		}
		resp := map[string]any{
			"enforced": true,
			"status":   provider.Status(),
		}
		json.NewEncoder(w).Encode(resp)
	}
}
