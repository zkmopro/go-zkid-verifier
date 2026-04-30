package linkverify

import (
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/zkmopro/go-zkid-verifier/issuercert"
	"github.com/zkmopro/go-zkid-verifier/smtroot"
	"github.com/zkmopro/go-zkid-verifier/verifier"
)

type Verifier struct {
	KeysDir             string
	SmtRoot             *smtroot.Provider
	IssuerCert          *issuercert.Provider
	ExpectedAppID       string // 62-char lowercase hex; for response display
	ExpectedAppIDPacked string // little-endian packed decimal; matched constant-time
	Logger              smtroot.Logger
}

// Result holds everything the handler needs to respond.
type Result struct {
	Verified      bool
	Reason        string
	Signals       *PublicSignals
	Parsed        *verifier.ParsedInputs
	SmtRoot       *SmtRootOutcome
	IssuerModulus *IssuerModulusOutcome
	AppID         *AppIDOutcome
	Challenge     *ChallengeOutcome
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

type IssuerModulusOutcome struct {
	Issuer         smtroot.IssuerID `json:"-"`
	IssuerName     string           `json:"issuer"`
	Match          bool             `json:"match"`
	ExpectedSHA256 string           `json:"expected_sha256"`
	TrustSource    string           `json:"trust_source,omitempty"`
	TrustedAt      time.Time        `json:"trusted_at,omitempty"`
}

type AppIDOutcome struct {
	Match    bool   `json:"match"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
}

// ChallengeOutcome reports whether the per-session challenge in the device-sig
// proof matches the value the verifier issued for this challenge.
type ChallengeOutcome struct {
	Match    bool   `json:"match"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
}

func (v *Verifier) Verify(req Request) (*Result, error) {
	ffiVerified, signals, err := Verify(req, v.KeysDir)
	if err != nil {
		return nil, err
	}
	if !ffiVerified {
		return &Result{Verified: false, Reason: ReasonProofInvalid, Signals: signals}, nil
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

	if v.SmtRoot != nil {
		outcome, err := checkSmtRoot(req.ProofType, parsed, v.SmtRoot, v.Logger)
		if err != nil {
			return nil, err
		}
		res.SmtRoot = outcome
		if !outcome.Match {
			res.Verified = false
			res.Reason = ReasonSmtRootMismatch
		}
	}

	if v.IssuerCert != nil {
		outcome, err := checkIssuerModulus(req.ProofType, parsed, v.IssuerCert, v.Logger)
		if err != nil {
			return nil, err
		}
		res.IssuerModulus = outcome
		if !outcome.Match && res.Reason == "" {
			res.Verified = false
			res.Reason = ReasonIssuerModulusMismatch
		}
	}

	if v.ExpectedAppIDPacked != "" {
		outcome := checkAppID(parsed, v.ExpectedAppID, v.ExpectedAppIDPacked, v.Logger)
		res.AppID = outcome
		if !outcome.Match && res.Reason == "" {
			res.Verified = false
			res.Reason = ReasonAppIDMismatch
		}
	}
	return res, nil
}

// CheckChallenge compares the per-session challenge in the proof against the
// value issued for this challenge (constant-time). Lives on Verifier so
// the service layer can reuse it after the FFI verify completes.
func (v *Verifier) CheckChallenge(parsed *verifier.ParsedInputs, expected string) *ChallengeOutcome {
	match := subtle.ConstantTimeCompare([]byte(parsed.Challenge), []byte(expected)) == 1
	outcome := &ChallengeOutcome{
		Match:    match,
		Expected: expected,
		Observed: parsed.Challenge,
	}
	level, event := "info", "challenge_check"
	if !match {
		level, event = "warn", "challenge_mismatch"
	}
	v.Logger.Event(level, event,
		"expected", outcome.Expected,
		"observed", outcome.Observed,
		"match", outcome.Match,
	)
	return outcome
}

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

func checkIssuerModulus(pt ProofType, parsed *verifier.ParsedInputs, provider *issuercert.Provider, logger smtroot.Logger) (*IssuerModulusOutcome, error) {
	issuer := issuerForProofType(pt)
	rec, meta, ok := provider.TrustedWithMeta(issuer)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrIssuerCertUnavailable, issuer.LongName())
	}
	if got, want := len(parsed.IssuerRSAModulus), len(rec.Limbs); got != want {
		return nil, fmt.Errorf("issuer modulus limb count: got %d, want %d for %s", got, want, issuer.LongName())
	}
	match := issuercert.LimbsEqual(rec.Limbs, parsed.IssuerRSAModulus)
	outcome := &IssuerModulusOutcome{
		Issuer:         issuer,
		IssuerName:     issuer.ShortName(),
		Match:          match,
		ExpectedSHA256: rec.SHA256Hex,
		TrustSource:    rec.Source,
		TrustedAt:      meta.UpdatedAt,
	}
	level, event := "info", "issuer_modulus_check"
	if !match {
		level, event = "warn", "issuer_modulus_mismatch"
	}
	logger.Event(level, event,
		"issuer", issuer.LongName(),
		"expected_sha256", outcome.ExpectedSHA256,
		"match", match,
		"trust_source", outcome.TrustSource,
		"cache_age_s", meta.CacheAgeSeconds,
	)
	return outcome, nil
}

// checkAppID compares the packed field-element form (constant-time on the
// decimal string), but reports the human-readable hex form so the response
// stays compatible with existing API clients.
func checkAppID(parsed *verifier.ParsedInputs, expectedHex, expectedPacked string, logger smtroot.Logger) *AppIDOutcome {
	match := subtle.ConstantTimeCompare([]byte(parsed.AppIDPacked), []byte(expectedPacked)) == 1
	outcome := &AppIDOutcome{
		Match:    match,
		Expected: expectedHex,
		Observed: parsed.AppID,
	}
	level, event := "info", "app_id_check"
	if !match {
		level, event = "warn", "app_id_mismatch"
	}
	logger.Event(level, event,
		"expected", outcome.Expected,
		"observed", outcome.Observed,
		"match", outcome.Match,
	)
	return outcome
}

// RS2048 → G2, RS4096 → G3.
func issuerForProofType(pt ProofType) smtroot.IssuerID {
	if pt == ProofTypeRS4096 {
		return smtroot.IssuerG3
	}
	return smtroot.IssuerG2
}
