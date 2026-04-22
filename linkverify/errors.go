package linkverify

import "errors"

// ErrSmtRootUnavailable — provider has no trusted root for the mapped issuer.
// Indicates startup fetch incomplete or all sources failing.
var ErrSmtRootUnavailable = errors.New("smtroot: trusted root unavailable")
