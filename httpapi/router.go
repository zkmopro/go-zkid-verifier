package httpapi

import (
	"net/http"

	"github.com/zkmopro/go-zkid-verifier/issuercert"
	"github.com/zkmopro/go-zkid-verifier/linkverify"
	"github.com/zkmopro/go-zkid-verifier/smtroot"
	"github.com/zkmopro/go-zkid-verifier/store"
)

func NewRouter(service *linkverify.Service, s store.Store, smtProvider *smtroot.Provider, issuerProvider *issuercert.Provider) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /challenge", createChallenge(s))
	mux.HandleFunc("GET /challenge/{id}", getChallenge(s))
	if service != nil {
		mux.HandleFunc("POST /link-verify", linkVerify(service))
	}
	mux.HandleFunc("GET /smt-root/status", smtRootStatus(smtProvider))
	mux.HandleFunc("GET /issuer-cert/status", issuerCertStatus(issuerProvider))
	return mux
}
