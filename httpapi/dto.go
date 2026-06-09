package httpapi

import (
	"github.com/privacy-ethereum/go-zkid-verifier/linkverify"
	"github.com/privacy-ethereum/go-zkid-verifier/verifier"
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
	Challenge     *linkverify.ChallengeOutcome     `json:"challenge,omitempty"`
}

type VerifyFailResponse struct {
	Verified      bool                             `json:"verified"`
	Reason        string                           `json:"reason,omitempty"`
	SmtRoot       *linkverify.SmtRootOutcome       `json:"smt_root,omitempty"`
	IssuerModulus *linkverify.IssuerModulusOutcome `json:"issuer_modulus,omitempty"`
	AppID         *linkverify.AppIDOutcome         `json:"app_id,omitempty"`
	Challenge     *linkverify.ChallengeOutcome     `json:"challenge,omitempty"`
}

type LinkVerifyRequest struct {
	CertChainType  string `json:"cert_chain_type"`
	CertChainProof []byte `json:"cert_chain_proof"`
	UserSigProof   []byte `json:"user_sig_proof"`
}
