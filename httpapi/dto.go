package httpapi

// JSON shapes in this file are the public /link-verify contract. Field tags
// and order must not drift; re-exporting internal pointer types keeps JSON
// output byte-identical to the pre-refactor response from package challenge.

import (
	"github.com/zkmopro/go-zkid-verifier/linkverify"
	"github.com/zkmopro/go-zkid-verifier/verifier"
)

type VerifySuccessResponse struct {
	Verified      bool                       `json:"verified"`
	Nullifier     string                     `json:"nullifier"`
	IDVerified    bool                       `json:"id_verified,omitempty"`
	Persisted     bool                       `json:"persisted,omitempty"`
	PublicSignals *linkverify.PublicSignals  `json:"public_signals,omitempty"`
	ParsedInputs  *verifier.ParsedInputs     `json:"parsed_inputs,omitempty"`
	SmtRoot       *linkverify.SmtRootOutcome `json:"smt_root,omitempty"`
}

type VerifyFailResponse struct {
	Verified bool                       `json:"verified"`
	Reason   string                     `json:"reason,omitempty"`
	SmtRoot  *linkverify.SmtRootOutcome `json:"smt_root,omitempty"`
}

type LinkVerifyRequest struct {
	CertChainType  string `json:"cert_chain_type"`
	CertChainProof []byte `json:"cert_chain_proof"`
	DeviceSigProof []byte `json:"device_sig_proof"`
}
