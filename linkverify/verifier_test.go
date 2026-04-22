package linkverify

import (
	"errors"
	"testing"

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
