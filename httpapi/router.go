package httpapi

import (
	"net/http"

	"github.com/zkmopro/go-zkid-verifier/issuercert"
	"github.com/zkmopro/go-zkid-verifier/linkverify"
	"github.com/zkmopro/go-zkid-verifier/smtroot"
	"github.com/zkmopro/go-zkid-verifier/store"
)

func NewRouter(service *linkverify.Service, s store.Store, smtProvider *smtroot.Provider, issuerProvider *issuercert.Provider, debugToken string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /challenge", createChallenge(s))
	mux.HandleFunc("GET /challenge/{id}", getChallenge(s))
	if service != nil {
		mux.HandleFunc("POST /link-verify", linkVerify(service))
	}
	mux.HandleFunc("GET /smt-root/status", smtRootStatus(smtProvider))
	mux.HandleFunc("GET /issuer-cert/status", issuerCertStatus(issuerProvider))
	if debugToken != "" {
		mux.HandleFunc("POST /debug/db/clean", cleanDB(s, debugToken))
	}
	return mux
}
