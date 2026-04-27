package linkverify

import (
	"errors"
	"testing"

	"github.com/zkmopro/go-zkid-verifier/issuercert"
	"github.com/zkmopro/go-zkid-verifier/smtroot"
	"github.com/zkmopro/go-zkid-verifier/verifier"
)

const (
	testRootA = "0x1111111111111111111111111111111111111111111111111111111111111111"
	testRootB = "0x2222222222222222222222222222222222222222222222222222222222222222"
)

func TestCheckSmtRoot_Match(t *testing.T) {
	provider := smtroot.NewStaticProvider(map[smtroot.IssuerID]smtroot.Root{
		smtroot.IssuerG2: mustRoot(t, testRootA),
	})
	parsed := &verifier.ParsedInputs{SmtRoot: testRootA}

	outcome, err := checkSmtRoot(ProofTypeRS2048, parsed, provider, noopLogger{})
	if err != nil {
		t.Fatalf("checkSmtRoot: %v", err)
	}
	if !outcome.Match {
		t.Fatalf("expected Match=true, got %+v", outcome)
	}
	if outcome.IssuerName != "g2" {
		t.Errorf("IssuerName = %q, want g2", outcome.IssuerName)
	}
	if outcome.TrustSource != "static" {
		t.Errorf("TrustSource = %q, want static", outcome.TrustSource)
	}
}

func TestCheckSmtRoot_Mismatch(t *testing.T) {
	provider := smtroot.NewStaticProvider(map[smtroot.IssuerID]smtroot.Root{
		smtroot.IssuerG2: mustRoot(t, testRootA),
	})
	parsed := &verifier.ParsedInputs{SmtRoot: testRootB}

	outcome, err := checkSmtRoot(ProofTypeRS2048, parsed, provider, noopLogger{})
	if err != nil {
		t.Fatalf("checkSmtRoot: %v", err)
	}
	if outcome.Match {
		t.Fatalf("expected Match=false on mismatch")
	}
	if outcome.Expected == outcome.Observed {
		t.Errorf("Expected == Observed on mismatch")
	}
}

func TestCheckSmtRoot_RS4096MapsToG3(t *testing.T) {
	provider := smtroot.NewStaticProvider(map[smtroot.IssuerID]smtroot.Root{
		smtroot.IssuerG3: mustRoot(t, testRootA),
		// Intentionally no G2; misrouting would surface as Unavailable.
	})
	parsed := &verifier.ParsedInputs{SmtRoot: testRootA}

	outcome, err := checkSmtRoot(ProofTypeRS4096, parsed, provider, noopLogger{})
	if err != nil {
		t.Fatalf("checkSmtRoot: %v", err)
	}
	if !outcome.Match || outcome.IssuerName != "g3" {
		t.Fatalf("expected match on g3, got %+v", outcome)
	}
}

func TestCheckSmtRoot_UnavailableWhenIssuerMissing(t *testing.T) {
	provider := smtroot.NewStaticProvider(map[smtroot.IssuerID]smtroot.Root{
		smtroot.IssuerG3: mustRoot(t, testRootA),
	})
	parsed := &verifier.ParsedInputs{SmtRoot: testRootA}

	_, err := checkSmtRoot(ProofTypeRS2048, parsed, provider, noopLogger{})
	if err == nil {
		t.Fatal("expected error when trusted root is missing for mapped issuer")
	}
	if !errors.Is(err, ErrSmtRootUnavailable) {
		t.Errorf("got %v, want ErrSmtRootUnavailable", err)
	}
}

func TestCheckSmtRoot_MalformedProofRoot(t *testing.T) {
	provider := smtroot.NewStaticProvider(map[smtroot.IssuerID]smtroot.Root{
		smtroot.IssuerG2: mustRoot(t, testRootA),
	})
	parsed := &verifier.ParsedInputs{SmtRoot: "0xZZZZ"}

	if _, err := checkSmtRoot(ProofTypeRS2048, parsed, provider, noopLogger{}); err == nil {
		t.Fatal("expected error on malformed proof smt_root")
	}
}

func mustRoot(t *testing.T, s string) smtroot.Root {
	t.Helper()
	r, err := smtroot.ParseRoot(s)
	if err != nil {
		t.Fatalf("ParseRoot(%q): %v", s, err)
	}
	return r
}

type noopLogger struct{}

func (noopLogger) Event(_, _ string, _ ...any) {}

var (
	limbsMatch    = []string{"0x01", "0x02", "0x03"}
	limbsMismatch = []string{"0x01", "0x02", "0x04"}
)

func stubCertRecord(limbs []string, source string) *issuercert.CertRecord {
	return &issuercert.CertRecord{Limbs: limbs, Source: source}
}

func TestCheckIssuerModulus_Match(t *testing.T) {
	provider := issuercert.NewStaticProvider(map[issuercert.IssuerID]*issuercert.CertRecord{
		issuercert.IssuerG2: stubCertRecord(limbsMatch, "embedded"),
	})
	parsed := &verifier.ParsedInputs{IssuerRSAModulus: limbsMatch}

	outcome, err := checkIssuerModulus(ProofTypeRS2048, parsed, provider, noopLogger{})
	if err != nil {
		t.Fatalf("checkIssuerModulus: %v", err)
	}
	if !outcome.Match {
		t.Fatalf("expected Match=true, got %+v", outcome)
	}
	if outcome.IssuerName != "g2" {
		t.Errorf("IssuerName = %q, want g2", outcome.IssuerName)
	}
	if outcome.TrustSource != "embedded" {
		t.Errorf("TrustSource = %q, want embedded", outcome.TrustSource)
	}
}

func TestCheckIssuerModulus_Mismatch(t *testing.T) {
	provider := issuercert.NewStaticProvider(map[issuercert.IssuerID]*issuercert.CertRecord{
		issuercert.IssuerG2: stubCertRecord(limbsMatch, "embedded"),
	})
	parsed := &verifier.ParsedInputs{IssuerRSAModulus: limbsMismatch}

	outcome, err := checkIssuerModulus(ProofTypeRS2048, parsed, provider, noopLogger{})
	if err != nil {
		t.Fatalf("checkIssuerModulus: %v", err)
	}
	if outcome.Match {
		t.Fatalf("expected Match=false on mismatch")
	}
}

func TestCheckIssuerModulus_RS4096MapsToG3(t *testing.T) {
	provider := issuercert.NewStaticProvider(map[issuercert.IssuerID]*issuercert.CertRecord{
		issuercert.IssuerG3: stubCertRecord(limbsMatch, "embedded"),
	})
	parsed := &verifier.ParsedInputs{IssuerRSAModulus: limbsMatch}

	outcome, err := checkIssuerModulus(ProofTypeRS4096, parsed, provider, noopLogger{})
	if err != nil {
		t.Fatalf("checkIssuerModulus: %v", err)
	}
	if !outcome.Match || outcome.IssuerName != "g3" {
		t.Fatalf("expected match on g3, got %+v", outcome)
	}
}

func TestCheckIssuerModulus_UnavailableWhenIssuerMissing(t *testing.T) {
	provider := issuercert.NewStaticProvider(map[issuercert.IssuerID]*issuercert.CertRecord{
		issuercert.IssuerG3: stubCertRecord(limbsMatch, "embedded"),
	})
	parsed := &verifier.ParsedInputs{IssuerRSAModulus: limbsMatch}

	_, err := checkIssuerModulus(ProofTypeRS2048, parsed, provider, noopLogger{})
	if err == nil {
		t.Fatal("expected error when trusted cert is missing for mapped issuer")
	}
	if !errors.Is(err, ErrIssuerCertUnavailable) {
		t.Errorf("got %v, want ErrIssuerCertUnavailable", err)
	}
}

func TestCheckAppID_Match(t *testing.T) {
	// Prover wire format: 0x-prefixed, 64-char zero-padded big-endian hex.
	// Operator config: bare decimal. Both must normalize to the same big.Int.
	parsed := &verifier.ParsedInputs{AppID: "0x0000000000000000000000000000000000000000000000000000000000000000"}
	outcome := checkAppID(parsed, "0", noopLogger{})
	if !outcome.Match {
		t.Fatalf("expected Match=true across wire/config formats, got %+v", outcome)
	}
}

func TestCheckAppID_Mismatch(t *testing.T) {
	parsed := &verifier.ParsedInputs{AppID: "0x0000000000000000000000000000000000000000000000000000000000000000"}
	outcome := checkAppID(parsed, "42", noopLogger{})
	if outcome.Match {
		t.Fatalf("expected Match=false, got %+v", outcome)
	}
	if outcome.Expected != "42" {
		t.Errorf("Expected: got %q, want %q", outcome.Expected, "42")
	}
}

func TestAppIDsEqual(t *testing.T) {
	cases := []struct {
		name           string
		observed       string
		expected       string
		want           bool
	}{
		{"hex-zero matches decimal-zero", "0x0000000000000000000000000000000000000000000000000000000000000000", "0", true},
		{"hex-42 matches decimal-42", "0x000000000000000000000000000000000000000000000000000000000000002a", "42", true},
		{"hex-42 matches hex-42 short", "0x000000000000000000000000000000000000000000000000000000000000002a", "0x2a", true},
		{"different values mismatch", "0x0000000000000000000000000000000000000000000000000000000000000000", "1", false},
		{"trims surrounding whitespace", "  0x00 ", "0", true},
		{"trims trailing newline on expected", "0x0000000000000000000000000000000000000000000000000000000000000000", "0\n", true},
		{"mid-string space fails parse", "0x 00", "0", false},
		{"unparseable observed", "not-a-number", "0", false},
		{"unparseable expected", "0", "not-a-number", false},
		{"empty expected", "0", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := appIDsEqual(c.observed, c.expected); got != c.want {
				t.Errorf("appIDsEqual(%q, %q) = %v, want %v", c.observed, c.expected, got, c.want)
			}
		})
	}
}

func TestCheckIssuerModulus_LimbCountMismatch(t *testing.T) {
	provider := issuercert.NewStaticProvider(map[issuercert.IssuerID]*issuercert.CertRecord{
		issuercert.IssuerG2: stubCertRecord(limbsMatch, "embedded"),
	})
	parsed := &verifier.ParsedInputs{IssuerRSAModulus: []string{"0x01"}}

	if _, err := checkIssuerModulus(ProofTypeRS2048, parsed, provider, noopLogger{}); err == nil {
		t.Fatal("expected error on limb count mismatch")
	}
}
