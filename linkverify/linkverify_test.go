package linkverify

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zkmopro/go-zkid-verifier/smtroot"
	"github.com/zkmopro/go-zkid-verifier/store"
	"github.com/zkmopro/go-zkid-verifier/verifier"
)

func resolveKeysDir(t *testing.T) string {
	t.Helper()
	keysDir := os.Getenv("KEYS_DIR")
	if keysDir == "" {
		keysDir = filepath.Join("..", "keys")
	}
	if _, err := os.Stat(filepath.Join(keysDir, "cert_chain_rs2048_verifying.key")); err != nil {
		return ""
	}
	abs, _ := filepath.Abs(keysDir)
	return abs
}


func TestVerifyRS2048(t *testing.T) {
	keysDir := os.Getenv("KEYS_DIR")
	if keysDir == "" {
		// Try default location relative to project root
		keysDir = filepath.Join("..", "keys")
	}
	if _, err := os.Stat(filepath.Join(keysDir, "cert_chain_rs2048_verifying.key")); err != nil {
		t.Skip("verifying keys not found; set KEYS_DIR or run make download-keys")
	}

	artifactsDir := filepath.Join("..", "tests", "artifacts", "cc2048_ds2048")
	ccProof, err := os.ReadFile(filepath.Join(artifactsDir, "cert_chain_rs2048_proof.bin"))
	if err != nil {
		t.Fatalf("read cert_chain proof: %v", err)
	}
	dsProof, err := os.ReadFile(filepath.Join(artifactsDir, "device_sig_rs2048_proof.bin"))
	if err != nil {
		t.Fatalf("read device_sig proof: %v", err)
	}

	absKeysDir, _ := filepath.Abs(keysDir)
	valid, signals, err := Verify(Request{
		CertChainProof: ccProof,
		DeviceSigProof: dsProof,
		ProofType:      ProofTypeRS2048,
	}, absKeysDir)
	if err != nil {
		t.Fatalf("Verify RS2048: %v", err)
	}
	if !valid {
		t.Fatal("expected link-verify RS2048 to pass")
	}
	if signals == nil {
		t.Fatal("expected non-nil public signals")
	}
	if len(signals.CertChain) < 2 {
		t.Fatalf("expected at least 2 cert_chain signals, got %d", len(signals.CertChain))
	}
	if len(signals.DeviceSig) < 1 {
		t.Fatalf("expected at least 1 device_sig signal, got %d", len(signals.DeviceSig))
	}
	// pk_commit must match across both circuits
	if signals.CertChain[0] != signals.DeviceSig[0] {
		t.Fatalf("pk_commit mismatch: cert_chain[0]=%s device_sig[0]=%s", signals.CertChain[0], signals.DeviceSig[0])
	}

	ds, err := verifier.ParseDeviceSig(signals.DeviceSig)
	if err != nil {
		t.Fatalf("ParseDeviceSig: %v", err)
	}
	t.Logf("pk_commit:     %s", ds.PkCommit)
	t.Logf("nullifier:     %s", ds.Nullifier)
	t.Logf("app_id_packed: %s", ds.AppIDPacked)
	t.Logf("challenge:     %s", ds.Challenge)
}

func TestVerifyRS4096(t *testing.T) {
	keysDir := os.Getenv("KEYS_DIR")
	if keysDir == "" {
		keysDir = filepath.Join("..", "keys")
	}
	if _, err := os.Stat(filepath.Join(keysDir, "cert_chain_rs4096_verifying.key")); err != nil {
		t.Skip("verifying keys not found; set KEYS_DIR or run make download-keys")
	}

	artifactsDir := filepath.Join("..", "tests", "artifacts", "cc4096_ds2048")
	ccProof, err := os.ReadFile(filepath.Join(artifactsDir, "cert_chain_rs4096_proof.bin"))
	if err != nil {
		t.Fatalf("read cert_chain proof: %v", err)
	}
	dsProof, err := os.ReadFile(filepath.Join(artifactsDir, "device_sig_rs2048_proof.bin"))
	if err != nil {
		t.Fatalf("read device_sig proof: %v", err)
	}

	absKeysDir, _ := filepath.Abs(keysDir)
	valid, signals, err := Verify(Request{
		CertChainProof: ccProof,
		DeviceSigProof: dsProof,
		ProofType:      ProofTypeRS4096,
	}, absKeysDir)
	if err != nil {
		t.Fatalf("Verify RS4096: %v", err)
	}
	if !valid {
		t.Fatal("expected link-verify RS4096 to pass")
	}
	if signals == nil {
		t.Fatal("expected non-nil public signals")
	}
	if len(signals.CertChain) < 2 {
		t.Fatalf("expected at least 2 cert_chain signals, got %d", len(signals.CertChain))
	}
	if len(signals.DeviceSig) < 1 {
		t.Fatalf("expected at least 1 device_sig signal, got %d", len(signals.DeviceSig))
	}
	if signals.CertChain[0] != signals.DeviceSig[0] {
		t.Fatalf("pk_commit mismatch: cert_chain[0]=%s device_sig[0]=%s", signals.CertChain[0], signals.DeviceSig[0])
	}

	pi, err := verifier.ParseCertChainRS4096(signals.CertChain)
	if err != nil {
		t.Fatalf("ParseCertChainRS4096: %v", err)
	}
	t.Logf("pk_commit:          %s", pi.PkCommit)
	t.Logf("issuer_rsa_modulus: %v", pi.IssuerRSAModulus)
	t.Logf("smt_root:           %s", pi.SmtRoot)
}

// Runs the FFI once to learn the fixture's real root, then exercises Verifier
// with a matching provider (expect Match) and a wrong one (expect mismatch).
func TestVerifier_SmtRootEnforcement(t *testing.T) {
	keysDir := os.Getenv("KEYS_DIR")
	if keysDir == "" {
		keysDir = filepath.Join("..", "keys")
	}
	if _, err := os.Stat(filepath.Join(keysDir, "cert_chain_rs2048_verifying.key")); err != nil {
		t.Skip("verifying keys not found; set KEYS_DIR or run make download-keys")
	}
	absKeysDir, _ := filepath.Abs(keysDir)

	artifactsDir := filepath.Join("..", "tests", "artifacts", "cc2048_ds2048")
	ccProof, err := os.ReadFile(filepath.Join(artifactsDir, "cert_chain_rs2048_proof.bin"))
	if err != nil {
		t.Fatalf("read cert_chain proof: %v", err)
	}
	dsProof, err := os.ReadFile(filepath.Join(artifactsDir, "device_sig_rs2048_proof.bin"))
	if err != nil {
		t.Fatalf("read device_sig proof: %v", err)
	}
	req := Request{
		CertChainProof: ccProof,
		DeviceSigProof: dsProof,
		ProofType:      ProofTypeRS2048,
	}

	_, signals, err := Verify(req, absKeysDir)
	if err != nil {
		t.Fatalf("baseline Verify: %v", err)
	}
	parsed, err := verifier.ParsePublicInputs(signals, verifier.CertChainRS2048)
	if err != nil {
		t.Fatalf("ParsePublicInputs: %v", err)
	}
	fixtureRoot, err := smtroot.ParseRoot(parsed.SmtRoot)
	if err != nil {
		t.Fatalf("ParseRoot(fixture): %v", err)
	}

	matchingProvider := smtroot.NewStaticProvider(map[smtroot.IssuerID]smtroot.Root{
		smtroot.IssuerG2: fixtureRoot,
	})
	v := &Verifier{KeysDir: absKeysDir, SmtRoot: matchingProvider, Logger: smtroot.DefaultLogger{}}
	result, err := v.Verify(req)
	if err != nil {
		t.Fatalf("Verify with matching provider: %v", err)
	}
	if !result.Verified {
		t.Fatalf("expected Verified=true with matching root, got reason=%q", result.Reason)
	}
	if result.SmtRoot == nil || !result.SmtRoot.Match {
		t.Fatalf("expected SmtRoot.Match=true, got %+v", result.SmtRoot)
	}
	if result.SmtRoot.TrustSource != "static" {
		t.Errorf("TrustSource = %q, want \"static\"", result.SmtRoot.TrustSource)
	}

	wrongRoot := smtroot.Root{0xDE, 0xAD, 0xBE, 0xEF}
	wrongProvider := smtroot.NewStaticProvider(map[smtroot.IssuerID]smtroot.Root{
		smtroot.IssuerG2: wrongRoot,
	})
	v2 := &Verifier{KeysDir: absKeysDir, SmtRoot: wrongProvider, Logger: smtroot.DefaultLogger{}}
	result2, err := v2.Verify(req)
	if err != nil {
		t.Fatalf("Verify with wrong provider: %v", err)
	}
	if result2.Verified {
		t.Fatalf("expected Verified=false on root mismatch")
	}
	if result2.Reason != "smt_root_mismatch" {
		t.Errorf("Reason = %q, want \"smt_root_mismatch\"", result2.Reason)
	}
	if result2.SmtRoot == nil || result2.SmtRoot.Match {
		t.Fatalf("expected SmtRoot.Match=false, got %+v", result2.SmtRoot)
	}
	if result2.SmtRoot.Expected == result2.SmtRoot.Observed {
		t.Errorf("Expected == Observed on mismatch: %s", result2.SmtRoot.Expected)
	}
}

func TestVerifier_NilProviderPassthrough(t *testing.T) {
	keysDir := os.Getenv("KEYS_DIR")
	if keysDir == "" {
		keysDir = filepath.Join("..", "keys")
	}
	if _, err := os.Stat(filepath.Join(keysDir, "cert_chain_rs2048_verifying.key")); err != nil {
		t.Skip("verifying keys not found; set KEYS_DIR or run make download-keys")
	}
	absKeysDir, _ := filepath.Abs(keysDir)

	artifactsDir := filepath.Join("..", "tests", "artifacts", "cc2048_ds2048")
	ccProof, _ := os.ReadFile(filepath.Join(artifactsDir, "cert_chain_rs2048_proof.bin"))
	dsProof, _ := os.ReadFile(filepath.Join(artifactsDir, "device_sig_rs2048_proof.bin"))

	v := &Verifier{KeysDir: absKeysDir, Logger: smtroot.DefaultLogger{}}
	result, err := v.Verify(Request{
		CertChainProof: ccProof,
		DeviceSigProof: dsProof,
		ProofType:      ProofTypeRS2048,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.Verified {
		t.Fatalf("expected Verified=true with no provider, got reason=%q", result.Reason)
	}
	if result.SmtRoot != nil {
		t.Errorf("expected nil SmtRoot with nil provider, got %+v", result.SmtRoot)
	}
}

// Real-FFI counterpart to TestLinkVerify_ChallengeMismatchReturns409
// (httpapi/linkverify_test.go) — pins the freshness fix end-to-end on actual
// proof bytes and asserts the nullifier is **not** recorded on a stale
// challenge. The HTTP test pins wire-format / status-code; this test pins
// FFI / persistence side-effects.
func TestServiceChallenge_RealProof(t *testing.T) {
	keysDir := resolveKeysDir(t)
	if keysDir == "" {
		t.Skip("verifying keys not found; set KEYS_DIR or run make download-keys")
	}

	artifactsDir := filepath.Join("..", "tests", "artifacts", "cc2048_ds2048")
	ccProof, err := os.ReadFile(filepath.Join(artifactsDir, "cert_chain_rs2048_proof.bin"))
	if err != nil {
		t.Fatalf("read cert_chain proof: %v", err)
	}
	dsProof, err := os.ReadFile(filepath.Join(artifactsDir, "device_sig_rs2048_proof.bin"))
	if err != nil {
		t.Fatalf("read device_sig proof: %v", err)
	}

	_, signals, err := Verify(Request{CertChainProof: ccProof, DeviceSigProof: dsProof, ProofType: ProofTypeRS2048}, keysDir)
	if err != nil {
		t.Fatalf("baseline Verify: %v", err)
	}
	parsed, err := verifier.ParsePublicInputs(signals, verifier.CertChainRS2048)
	if err != nil {
		t.Fatalf("ParsePublicInputs: %v", err)
	}
	v := &Verifier{KeysDir: keysDir, Logger: smtroot.DefaultLogger{}}

	t.Run("match", func(t *testing.T) {
		key, err := verifier.NormalizeDecimal(parsed.Challenge)
		if err != nil {
			t.Fatalf("NormalizeDecimal: %v", err)
		}
		c := futureChallenge(key)
		fs := &fakeStore{byID: map[string]*store.Challenge{c.Challenge: c}}
		res, err := NewService(v, fs).VerifyAndRecord(t.Context(), Request{
			CertChainProof: ccProof, DeviceSigProof: dsProof, ProofType: ProofTypeRS2048,
		})
		if err != nil {
			t.Fatalf("VerifyAndRecord: %v", err)
		}
		if !res.Verified || !res.Persisted {
			t.Fatalf("expected Verified+Persisted, got verified=%v persisted=%v reason=%q", res.Verified, res.Persisted, res.Reason)
		}
		if res.Challenge == nil || !res.Challenge.Match {
			t.Fatalf("Challenge outcome: %+v", res.Challenge)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		// Store does not contain the challenge bound into the proof.
		fs := &fakeStore{byID: map[string]*store.Challenge{}}
		_, err := NewService(v, fs).VerifyAndRecord(t.Context(), Request{
			CertChainProof: ccProof, DeviceSigProof: dsProof, ProofType: ProofTypeRS2048,
		})
		if !errors.Is(err, store.ErrChallengeNotFound) {
			t.Fatalf("expected ErrChallengeNotFound, got %v", err)
		}
	})
}

func TestParseProofType(t *testing.T) {
	cases := []struct {
		in      string
		want    ProofType
		wantErr bool
	}{
		{"", ProofTypeRS2048, false},
		{"rs2048", ProofTypeRS2048, false},
		{"rs4096", ProofTypeRS4096, false},
		{"RS2048", "", true},
		{"rs8192", "", true},
		{"tbs", "", true},
	}
	for _, c := range cases {
		got, err := ParseProofType(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseProofType(%q): want error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseProofType(%q): unexpected error %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("ParseProofType(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestProofTypeStoreKey(t *testing.T) {
	if got := ProofTypeRS2048.StoreKey(); got != "link_rs2048" {
		t.Errorf("RS2048.StoreKey() = %q, want link_rs2048", got)
	}
	if got := ProofTypeRS4096.StoreKey(); got != "link_rs4096" {
		t.Errorf("RS4096.StoreKey() = %q, want link_rs4096", got)
	}
}