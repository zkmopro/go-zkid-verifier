package httpapi

import (
	"net/http"

	"github.com/privacy-ethereum/go-zkid-verifier/issuercert"
	"github.com/privacy-ethereum/go-zkid-verifier/linkverify"
	"github.com/privacy-ethereum/go-zkid-verifier/smtroot"
	"github.com/privacy-ethereum/go-zkid-verifier/store"
)

func NewRouter(service *linkverify.Service, s store.Store, smtProvider *smtroot.Provider, issuerProvider *issuercert.Provider, appID, debugToken string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /challenge", createChallenge(s, appID))
	mux.HandleFunc("GET /challenge/{challenge}", getChallenge(s, appID))
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
