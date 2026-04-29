package httpapi

import (
	"github.com/zkmopro/go-zkid-verifier/linkverify"
	"github.com/zkmopro/go-zkid-verifier/verifier"
)

type VerifySuccessResponse struct {
	Verified      bool                             `json:"verified"`
	Nullifier     string                           `json:"nullifier"`
	IDVerified    bool                             `json:"id_verified,omitempty"`
	Persisted     bool                             `json:"persisted,omitempty"`
	PublicSignals *linkverify.PublicSignals        `json:"public_signals,omitempty"`
	ParsedInputs  *verifier.ParsedInputs           `json:"parsed_inputs,omitempty"`
	SmtRoot       *linkverify.SmtRootOutcome       `json:"smt_root,omitempty"`
	IssuerModulus *linkverify.IssuerModulusOutcome `json:"issuer_modulus,omitempty"`
	AppID         *linkverify.AppIDOutcome         `json:"app_id,omitempty"`
}

type VerifyFailResponse struct {
	Verified      bool                             `json:"verified"`
	Reason        string                           `json:"reason,omitempty"`
	SmtRoot       *linkverify.SmtRootOutcome       `json:"smt_root,omitempty"`
	IssuerModulus *linkverify.IssuerModulusOutcome `json:"issuer_modulus,omitempty"`
	AppID         *linkverify.AppIDOutcome         `json:"app_id,omitempty"`
}

type LinkVerifyRequest struct {
	ChallengeID    string `json:"challenge_id"`
	CertChainType  string `json:"cert_chain_type"`
	CertChainProof []byte `json:"cert_chain_proof"`
	DeviceSigProof []byte `json:"device_sig_proof"`
}
