package linkverify

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/zkmopro/go-zkid-verifier/issuercert"
	"github.com/zkmopro/go-zkid-verifier/smtroot"
	"github.com/zkmopro/go-zkid-verifier/verifier"
)


type Verifier struct {
	KeysDir       string
	SmtRoot       *smtroot.Provider
	IssuerCert    *issuercert.Provider
	ExpectedAppID string
	Logger        smtroot.Logger
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

	if v.ExpectedAppID != "" {
		outcome := checkAppID(parsed, v.ExpectedAppID, v.Logger)
		res.AppID = outcome
		if !outcome.Match && res.Reason == "" {
			res.Verified = false
			res.Reason = ReasonAppIDMismatch
		}
	}
	return res, nil
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

func checkAppID(parsed *verifier.ParsedInputs, expected string, logger smtroot.Logger) *AppIDOutcome {
	outcome := &AppIDOutcome{
		Match:    appIDsEqual(parsed.AppID, expected),
		Expected: expected,
		Observed: parsed.AppID,
	}
	level, event := "info", "app_id_check"
	if !outcome.Match {
		level, event = "warn", "app_id_mismatch"
	}
	logger.Event(level, event,
		"expected", outcome.Expected,
		"observed", outcome.Observed,
		"match", outcome.Match,
	)
	return outcome
}

// appIDsEqual compares two app_id strings as field-element values, normalizing
// across the prover's wire format ("0x" + 64-char zero-padded big-endian hex,
// e.g. "0x000…000" for 0) and operator-supplied env values ("0", "42", "0x2a").
// Both forms parse to the same big.Int; mismatches return false rather than
// erroring so a malformed value naturally fails the check.
func appIDsEqual(observed, expected string) bool {
	o, ok := parseAppID(observed)
	if !ok {
		return false
	}
	e, ok := parseAppID(expected)
	if !ok {
		return false
	}
	return o.Cmp(e) == 0
}

func parseAppID(s string) (*big.Int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
		base = 16
	}
	n, ok := new(big.Int).SetString(s, base)
	return n, ok
}

// RS2048 → G2, RS4096 → G3.
func issuerForProofType(pt ProofType) smtroot.IssuerID {
	if pt == ProofTypeRS4096 {
		return smtroot.IssuerG3
	}
	return smtroot.IssuerG2
}
