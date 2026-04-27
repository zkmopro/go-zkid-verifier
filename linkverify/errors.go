package linkverify

import "errors"

// ErrSmtRootUnavailable indicates no trusted root is available.
var ErrSmtRootUnavailable = errors.New("smtroot: trusted root unavailable")

var ErrIssuerCertUnavailable = errors.New("issuercert: trusted cert unavailable")

const (
	ReasonProofInvalid          = "proof_invalid"
	ReasonSmtRootMismatch       = "smt_root_mismatch"
	ReasonIssuerModulusMismatch = "issuer_modulus_mismatch"
	ReasonAppIDMismatch         = "app_id_mismatch"
)
