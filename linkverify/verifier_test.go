package linkverify

import (
	"errors"
	"testing"

	"github.com/zkmopro/go-zkid-verifier/smtroot"
)

// buildSignals — RS2048: 20 cert_chain elems, smt_root at 19. RS4096: 37, smt_root at 36.
func buildSignals(pt ProofType, smtRoot, pkCommit string) *PublicSignals {
	n := 20
	if pt == ProofTypeRS4096 {
		n = 37
	}
	cc := make([]string, n)
	for i := range cc {
		cc[i] = "0x00"
	}
	cc[1] = pkCommit
	cc[n-1] = smtRoot
	ds := []string{pkCommit, "0x" + packedChallenge("hi")}
	return &PublicSignals{CertChain: cc, DeviceSig: ds}
}

// packedChallenge produces the TBS field element the circuit emits: ASCII
// challenge + 0x80 SHA-256 pad marker, packed little-endian into 31 bytes,
// serialised as big-endian hex.
func packedChallenge(challenge string) string {
	const fieldBytes = 32
	const bytesPerField = 31
	data := make([]byte, bytesPerField)
	copy(data, challenge)
	data[len(challenge)] = 0x80
	buf := make([]byte, fieldBytes)
	for i, b := range data {
		buf[fieldBytes-1-i] = b
	}
	return hex32(buf)
}

func hex32(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, 64)
	for i, v := range b {
		out[i*2] = hexChars[v>>4]
		out[i*2+1] = hexChars[v&0xF]
	}
	return string(out)
}

const (
	testRootA = "0x1111111111111111111111111111111111111111111111111111111111111111"
	testRootB = "0x2222222222222222222222222222222222222222222222222222222222222222"
)

func TestVerifier_MatchWithProvider(t *testing.T) {
	provider := smtroot.NewStaticProvider(map[smtroot.IssuerID]smtroot.Root{
		smtroot.IssuerG2: mustRoot(t, testRootA),
	})
	v := &Verifier{
		KeysDir: "",
		SmtRoot: provider,
		Logger:  noopLogger{},
		verifyFn: func(_ Request, _ string) (bool, *PublicSignals, error) {
			return true, buildSignals(ProofTypeRS2048, testRootA, "0xAA"), nil
		},
	}

	result, err := v.Verify(Request{ProofType: ProofTypeRS2048})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.Verified {
		t.Fatalf("expected Verified=true, got reason=%q", result.Reason)
	}
	if result.SmtRoot == nil || !result.SmtRoot.Match {
		t.Fatalf("expected SmtRoot.Match=true, got %+v", result.SmtRoot)
	}
	if result.SmtRoot.IssuerName != "g2" {
		t.Errorf("IssuerName = %q, want g2", result.SmtRoot.IssuerName)
	}
	if result.SmtRoot.TrustSource != "static" {
		t.Errorf("TrustSource = %q, want static", result.SmtRoot.TrustSource)
	}
}

func TestVerifier_MismatchWithProvider(t *testing.T) {
	provider := smtroot.NewStaticProvider(map[smtroot.IssuerID]smtroot.Root{
		smtroot.IssuerG2: mustRoot(t, testRootA),
	})
	v := &Verifier{
		SmtRoot: provider,
		Logger:  noopLogger{},
		verifyFn: func(_ Request, _ string) (bool, *PublicSignals, error) {
			return true, buildSignals(ProofTypeRS2048, testRootB, "0xAA"), nil
		},
	}

	result, err := v.Verify(Request{ProofType: ProofTypeRS2048})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verified {
		t.Fatalf("expected Verified=false on mismatch")
	}
	if result.Reason != "smt_root_mismatch" {
		t.Errorf("Reason = %q, want smt_root_mismatch", result.Reason)
	}
	if result.SmtRoot == nil {
		t.Fatalf("expected non-nil SmtRoot")
	}
	if result.SmtRoot.Match {
		t.Fatalf("expected SmtRoot.Match=false, got true")
	}
	if result.SmtRoot.Expected == result.SmtRoot.Observed {
		t.Errorf("Expected == Observed on mismatch")
	}
}

func TestVerifier_RS4096MapsToG3(t *testing.T) {
	provider := smtroot.NewStaticProvider(map[smtroot.IssuerID]smtroot.Root{
		smtroot.IssuerG3: mustRoot(t, testRootA),
		// Intentionally no G2; a misrouting would surface as Unavailable.
	})
	v := &Verifier{
		SmtRoot: provider,
		Logger:  noopLogger{},
		verifyFn: func(_ Request, _ string) (bool, *PublicSignals, error) {
			return true, buildSignals(ProofTypeRS4096, testRootA, "0xAA"), nil
		},
	}
	result, err := v.Verify(Request{ProofType: ProofTypeRS4096})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.Verified || !result.SmtRoot.Match {
		t.Fatalf("expected RS4096 to match G3, got result=%+v", result)
	}
	if result.SmtRoot.IssuerName != "g3" {
		t.Errorf("IssuerName = %q, want g3", result.SmtRoot.IssuerName)
	}
}

func TestVerifier_NoEnforcementWhenProviderNil(t *testing.T) {
	v := &Verifier{
		Logger: noopLogger{},
		verifyFn: func(_ Request, _ string) (bool, *PublicSignals, error) {
			return true, buildSignals(ProofTypeRS2048, testRootA, "0xAA"), nil
		},
	}
	result, err := v.Verify(Request{ProofType: ProofTypeRS2048})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.Verified {
		t.Fatalf("expected Verified=true with nil provider")
	}
	if result.SmtRoot != nil {
		t.Errorf("expected nil SmtRoot with nil provider, got %+v", result.SmtRoot)
	}
}

func TestVerifier_UnavailableWhenIssuerMissing(t *testing.T) {
	provider := smtroot.NewStaticProvider(map[smtroot.IssuerID]smtroot.Root{
		smtroot.IssuerG3: mustRoot(t, testRootA), // only G3 loaded
	})
	v := &Verifier{
		SmtRoot: provider,
		Logger:  noopLogger{},
		verifyFn: func(_ Request, _ string) (bool, *PublicSignals, error) {
			return true, buildSignals(ProofTypeRS2048, testRootA, "0xAA"), nil
		},
	}
	_, err := v.Verify(Request{ProofType: ProofTypeRS2048})
	if err == nil {
		t.Fatal("expected error when trusted root is missing for mapped issuer")
	}
	if !errors.Is(err, ErrSmtRootUnavailable) {
		t.Errorf("got %v, want ErrSmtRootUnavailable", err)
	}
}

func TestVerifier_FFIReturnsFalse(t *testing.T) {
	provider := smtroot.NewStaticProvider(map[smtroot.IssuerID]smtroot.Root{
		smtroot.IssuerG2: mustRoot(t, testRootA),
	})
	v := &Verifier{
		SmtRoot: provider,
		Logger:  noopLogger{},
		verifyFn: func(_ Request, _ string) (bool, *PublicSignals, error) {
			return false, nil, nil
		},
	}
	result, err := v.Verify(Request{ProofType: ProofTypeRS2048})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verified {
		t.Fatalf("expected Verified=false when FFI rejects")
	}
	if result.Reason != "proof_invalid" {
		t.Errorf("Reason = %q, want proof_invalid", result.Reason)
	}
	if result.SmtRoot != nil {
		t.Errorf("expected SmtRoot=nil when proof is invalid (no need to check)")
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
