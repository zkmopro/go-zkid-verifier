package linkverify

import "errors"

// ErrSmtRootUnavailable indicates no trusted root is available.
var ErrSmtRootUnavailable = errors.New("smtroot: trusted root unavailable")

const (
	ReasonProofInvalid    = "proof_invalid"
	ReasonSmtRootMismatch = "smt_root_mismatch"
)
