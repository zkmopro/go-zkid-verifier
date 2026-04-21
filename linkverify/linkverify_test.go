package linkverify

import (
	"os"
	"path/filepath"
	"testing"

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
	t.Logf("serial_number:      %s", pi.SerialNumber)
}
