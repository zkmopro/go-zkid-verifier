package httpapi

import (
	"net/http"

	"github.com/zkmopro/go-zkid-verifier/linkverify"
	"github.com/zkmopro/go-zkid-verifier/smtroot"
	"github.com/zkmopro/go-zkid-verifier/store"
)

// NewRouter builds the http.Handler for all REST endpoints. A nil service
// omits /link-verify (tests that only exercise /challenge routes). A nil
// provider reports enforcement disabled on /smt-root/status.
func NewRouter(service *linkverify.Service, s store.Store, provider *smtroot.Provider) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /challenge", createChallenge(s))
	mux.HandleFunc("GET /challenge/{id}", getChallenge(s))
	if service != nil {
		mux.HandleFunc("POST /link-verify", linkVerify(service))
	}
	mux.HandleFunc("GET /smt-root/status", smtRootStatus(provider))
	return mux
}
