package linkverify

import (
	"os"
	"path/filepath"
	"testing"
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
	valid, err := Verify(Request{
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
	valid, err := Verify(Request{
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
}
