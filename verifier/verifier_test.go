package verifier

import (
	"os"
	"path/filepath"
	"testing"
)

// setupVerifyDir creates a temp directory with the structure expected by LinkVerify:
//
//	{tmpDir}/keys/{proof files} + symlinks to verifying keys
func setupVerifyDir(t *testing.T, artifactsDir, keysDir string, proofFiles []string, vkFiles []string) string {
	t.Helper()

	tmpDir := t.TempDir()
	tmpKeys := filepath.Join(tmpDir, "keys")
	if err := os.Mkdir(tmpKeys, 0o755); err != nil {
		t.Fatalf("create temp keys dir: %v", err)
	}

	for _, name := range proofFiles {
		data, err := os.ReadFile(filepath.Join(artifactsDir, name))
		if err != nil {
			t.Fatalf("read proof %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(tmpKeys, name), data, 0o600); err != nil {
			t.Fatalf("write proof %s: %v", name, err)
		}
	}

	for _, name := range vkFiles {
		src, _ := filepath.Abs(filepath.Join(keysDir, name))
		dst := filepath.Join(tmpKeys, name)
		if err := os.Symlink(src, dst); err != nil {
			t.Fatalf("symlink %s: %v", name, err)
		}
	}

	return tmpDir
}

func TestLinkVerifyRS2048(t *testing.T) {
	keysDir := os.Getenv("KEYS_DIR")
	if keysDir == "" {
		keysDir = filepath.Join("..", "keys")
	}
	if _, err := os.Stat(filepath.Join(keysDir, "cert_chain_rs2048_verifying.key")); err != nil {
		t.Skip("verifying keys not found; set KEYS_DIR or run make download-keys")
	}

	absKeysDir, _ := filepath.Abs(keysDir)
	artifactsDir := filepath.Join("..", "tests", "artifacts", "cc2048_ds2048")
	tmpDir := setupVerifyDir(t, artifactsDir, absKeysDir,
		[]string{"cert_chain_rs2048_proof.bin", "user_sig_rs2048_proof.bin"},
		[]string{"cert_chain_rs2048_verifying.key", "user_sig_rs2048_verifying.key"},
	)

	valid, signals, err := LinkVerify(tmpDir, CertChainRS2048)
	if err != nil {
		t.Fatalf("LinkVerify RS2048: %v", err)
	}
	if !valid {
		t.Fatal("expected link-verify RS2048 to pass")
	}
	if signals == nil {
		t.Fatal("expected non-nil public signals")
	}
	t.Logf("cert_chain signals: %v", signals.CertChain)
	t.Logf("device_sig signals: %v", signals.DeviceSig)
}

func TestLinkVerifyRS4096(t *testing.T) {
	keysDir := os.Getenv("KEYS_DIR")
	if keysDir == "" {
		keysDir = filepath.Join("..", "keys")
	}
	if _, err := os.Stat(filepath.Join(keysDir, "cert_chain_rs4096_verifying.key")); err != nil {
		t.Skip("verifying keys not found; set KEYS_DIR or run make download-keys")
	}

	absKeysDir, _ := filepath.Abs(keysDir)
	artifactsDir := filepath.Join("..", "tests", "artifacts", "cc4096_ds2048")
	tmpDir := setupVerifyDir(t, artifactsDir, absKeysDir,
		[]string{"cert_chain_rs4096_proof.bin", "user_sig_rs2048_proof.bin"},
		[]string{"cert_chain_rs4096_verifying.key", "user_sig_rs2048_verifying.key"},
	)

	valid, signals, err := LinkVerify(tmpDir, CertChainRS4096)
	if err != nil {
		t.Fatalf("LinkVerify RS4096: %v", err)
	}
	if !valid {
		t.Fatal("expected link-verify RS4096 to pass")
	}
	if signals == nil {
		t.Fatal("expected non-nil public signals")
	}
	t.Logf("cert_chain signals: %v", signals.CertChain)
	t.Logf("device_sig signals: %v", signals.DeviceSig)
}
