package linkverify

import "errors"

// ErrSmtRootUnavailable — provider has no trusted root for the mapped issuer.
// Indicates startup fetch incomplete or all sources failing.
var ErrSmtRootUnavailable = errors.New("smtroot: trusted root unavailable")

// Reason values carried in Result.Reason. Transports branch on these
// strings to pick HTTP status codes / gRPC codes.
const (
	ReasonProofInvalid    = "proof_invalid"
	ReasonSmtRootMismatch = "smt_root_mismatch"
)
