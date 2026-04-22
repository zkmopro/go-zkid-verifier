package linkverify

import (
	"fmt"
	"time"

	"github.com/zkmopro/go-zkid-verifier/smtroot"
	"github.com/zkmopro/go-zkid-verifier/verifier"
)

// Verifier orchestrates link-verify with optional SMT-root enforcement.
// A nil SmtRoot disables root checking — production must configure it; nil is
// for tests and local dev with historical fixtures.
type Verifier struct {
	KeysDir string
	SmtRoot *smtroot.Provider
	Logger  smtroot.Logger
}

// Result holds everything the handler needs to respond.
type Result struct {
	Verified bool
	Reason   string
	Signals  *PublicSignals
	Parsed   *verifier.ParsedInputs
	SmtRoot  *SmtRootOutcome
}

// SmtRootOutcome is the outcome of the proof-vs-trusted-root comparison.
type SmtRootOutcome struct {
	Issuer      smtroot.IssuerID `json:"-"`
	IssuerName  string           `json:"issuer"`
	Match       bool             `json:"match"`
	Expected    string           `json:"expected"`
	Observed    string           `json:"observed"`
	TrustSource string           `json:"trust_source,omitempty"`
	TrustedAt   time.Time        `json:"trusted_at,omitempty"`
}

// Verify returns a non-nil Result whenever the FFI did not error. An error is
// returned only for infrastructure failures (FFI crash, malformed signals,
// missing trusted root for the mapped issuer).
func (v *Verifier) Verify(req Request) (*Result, error) {
	ffiVerified, signals, err := Verify(req, v.KeysDir)
	if err != nil {
		return nil, err
	}
	if !ffiVerified {
		return &Result{Verified: false, Reason: "proof_invalid", Signals: signals}, nil
	}

	certChainType := verifier.CertChainRS2048
	if req.ProofType == ProofTypeRS4096 {
		certChainType = verifier.CertChainRS4096
	}
	parsed, err := verifier.ParsePublicInputs(signals, certChainType)
	if err != nil {
		return nil, fmt.Errorf("parse public inputs: %w", err)
	}

	res := &Result{Verified: true, Signals: signals, Parsed: parsed}
	if v.SmtRoot == nil {
		return res, nil
	}

	outcome, err := checkSmtRoot(req.ProofType, parsed, v.SmtRoot, v.Logger)
	if err != nil {
		return nil, err
	}
	res.SmtRoot = outcome
	if !outcome.Match {
		res.Verified = false
		res.Reason = "smt_root_mismatch"
	}
	return res, nil
}

// checkSmtRoot compares the proof's smt_root public input against the trusted
// root for the issuer derived from pt. Pure function: callers own provider and
// logger lifetimes.
func checkSmtRoot(pt ProofType, parsed *verifier.ParsedInputs, provider *smtroot.Provider, logger smtroot.Logger) (*SmtRootOutcome, error) {
	issuer := issuerForProofType(pt)
	observed, err := smtroot.ParseRoot(parsed.SmtRoot)
	if err != nil {
		return nil, fmt.Errorf("parse proof smt_root %q: %w", parsed.SmtRoot, err)
	}
	trusted, ok := provider.Trusted(issuer)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSmtRootUnavailable, issuer.LongName())
	}
	meta := provider.Meta()
	outcome := &SmtRootOutcome{
		Issuer:      issuer,
		IssuerName:  issuer.ShortName(),
		Match:       observed.Equal(trusted),
		Expected:    trusted.Hex(),
		Observed:    observed.Hex(),
		TrustSource: meta.SourceUsed,
		TrustedAt:   meta.UpdatedAt,
	}
	level, event := "info", "smt_root_check"
	if !outcome.Match {
		level, event = "warn", "smt_root_mismatch"
	}
	logger.Event(level, event,
		"issuer", issuer.LongName(),
		"expected", outcome.Expected,
		"observed", outcome.Observed,
		"match", outcome.Match,
		"trust_source", outcome.TrustSource,
		"cache_age_s", meta.CacheAgeSeconds,
	)
	return outcome, nil
}

// RS2048 → G2, RS4096 → G3.
func issuerForProofType(pt ProofType) smtroot.IssuerID {
	if pt == ProofTypeRS4096 {
		return smtroot.IssuerG3
	}
	return smtroot.IssuerG2
}
