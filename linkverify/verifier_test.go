package linkverify

import (
	"errors"
	"testing"

	"github.com/privacy-ethereum/go-zkid-verifier/issuercert"
	"github.com/privacy-ethereum/go-zkid-verifier/smtroot"
	"github.com/privacy-ethereum/go-zkid-verifier/verifier"
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
	parsed := &verifier.ParsedInputs{AppID: "0xabc123"}
	outcome := checkAppID(parsed, "0xabc123", noopLogger{})
	if !outcome.Match {
		t.Fatalf("expected Match=true, got %+v", outcome)
	}
	if outcome.Expected != "0xabc123" || outcome.Observed != "0xabc123" {
		t.Errorf("expected/observed: %+v", outcome)
	}
}

func TestCheckAppID_Mismatch(t *testing.T) {
	parsed := &verifier.ParsedInputs{AppID: "0xabc123"}
	outcome := checkAppID(parsed, "0xdef456", noopLogger{})
	if outcome.Match {
		t.Fatalf("expected Match=false, got %+v", outcome)
	}
	if outcome.Expected != "0xdef456" {
		t.Errorf("Expected: got %q", outcome.Expected)
	}
}

func TestCheckChallenge_Match(t *testing.T) {
	v := &Verifier{Logger: noopLogger{}}
	parsed := &verifier.ParsedInputs{Challenge: "12345"}
	outcome := v.CheckChallenge(parsed, "12345")
	if !outcome.Match {
		t.Fatalf("expected Match=true, got %+v", outcome)
	}
}

func TestCheckChallenge_Mismatch(t *testing.T) {
	v := &Verifier{Logger: noopLogger{}}
	parsed := &verifier.ParsedInputs{Challenge: "12345"}
	outcome := v.CheckChallenge(parsed, "67890")
	if outcome.Match {
		t.Fatalf("expected Match=false, got %+v", outcome)
	}
	if outcome.Expected != "67890" || outcome.Observed != "12345" {
		t.Errorf("expected/observed: %+v", outcome)
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
