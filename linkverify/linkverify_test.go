package linkverify

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zkmopro/go-zkid-verifier/smtroot"
	"github.com/zkmopro/go-zkid-verifier/verifier"
)

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
	if signals.CertChain[1] != signals.DeviceSig[0] {
		t.Fatalf("pk_commit mismatch: cert_chain[1]=%s device_sig[0]=%s", signals.CertChain[1], signals.DeviceSig[0])
	}

	ds, err := verifier.ParseDeviceSig(signals.DeviceSig)
	if err != nil {
		t.Fatalf("ParseDeviceSig: %v", err)
	}
	challenge, err := ds.Challenge()
	if err != nil {
		t.Fatalf("Challenge(): %v", err)
	}
	t.Logf("pk_commit:  %s", ds.PkCommit)
	t.Logf("challenge:  %s", challenge)
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
	if signals.CertChain[1] != signals.DeviceSig[0] {
		t.Fatalf("pk_commit mismatch: cert_chain[1]=%s device_sig[0]=%s", signals.CertChain[1], signals.DeviceSig[0])
	}

	pi, err := verifier.ParseCertChainRS4096(signals.CertChain)
	if err != nil {
		t.Fatalf("ParseCertChainRS4096: %v", err)
	}
	t.Logf("subject_dn_hash:    %s", pi.SubjectDNHash)
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
	v := NewVerifier(absKeysDir, matchingProvider)
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
	v2 := NewVerifier(absKeysDir, wrongProvider)
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

	v := NewVerifier(absKeysDir, nil)
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
