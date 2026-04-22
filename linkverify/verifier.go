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

	// verifyFn is the FFI entry point; swapped in tests.
	verifyFn func(Request, string) (bool, *PublicSignals, error)
}

// NewVerifier — pass a nil provider to disable SMT root enforcement.
func NewVerifier(keysDir string, provider *smtroot.Provider) *Verifier {
	return &Verifier{
		KeysDir:  keysDir,
		SmtRoot:  provider,
		Logger:   smtroot.DefaultLogger{},
		verifyFn: Verify,
	}
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
	fn := v.verifyFn
	if fn == nil {
		fn = Verify
	}

	ffiVerified, signals, err := fn(req, v.KeysDir)
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

	outcome, err := v.checkRoot(req, parsed)
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

func (v *Verifier) checkRoot(req Request, parsed *verifier.ParsedInputs) (*SmtRootOutcome, error) {
	issuer := issuerForProofType(req.ProofType)
	observed, err := smtroot.ParseRoot(parsed.SmtRoot)
	if err != nil {
		return nil, fmt.Errorf("parse proof smt_root %q: %w", parsed.SmtRoot, err)
	}
	trusted, ok := v.SmtRoot.Trusted(issuer)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSmtRootUnavailable, issuer.LongName())
	}
	meta := v.SmtRoot.Meta()
	outcome := &SmtRootOutcome{
		Issuer:      issuer,
		IssuerName:  issuer.ShortName(),
		Match:       observed.Equal(trusted),
		Expected:    trusted.Hex(),
		Observed:    observed.Hex(),
		TrustSource: meta.SourceUsed,
		TrustedAt:   meta.UpdatedAt,
	}
	kv := []any{
		"issuer", issuer.LongName(),
		"expected", outcome.Expected,
		"observed", outcome.Observed,
		"match", outcome.Match,
		"trust_source", outcome.TrustSource,
		"cache_age_s", meta.CacheAgeSeconds,
	}
	logger := v.logger()
	if outcome.Match {
		logger.Event("info", "smt_root_check", kv...)
	} else {
		logger.Event("warn", "smt_root_mismatch", kv...)
	}
	return outcome, nil
}

// logger defends struct-literal test construction from panicking.
func (v *Verifier) logger() smtroot.Logger {
	if v.Logger == nil {
		return smtroot.DefaultLogger{}
	}
	return v.Logger
}

// RS2048 → G2, RS4096 → G3.
func issuerForProofType(pt ProofType) smtroot.IssuerID {
	if pt == ProofTypeRS4096 {
		return smtroot.IssuerG3
	}
	return smtroot.IssuerG2
}
