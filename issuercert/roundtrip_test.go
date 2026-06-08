//go:build integration

package issuercert_test

import (
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privacy-ethereum/go-zkid-verifier/issuercert"
	"github.com/privacy-ethereum/go-zkid-verifier/verifier"
)

func TestLimbConventionMatchesCircuit_RS2048(t *testing.T) {
	runLimbConvention(t, verifier.CertChainRS2048, 2048, issuercert.LimbsRS2048,
		"cc2048_ds2048",
		[]string{"cert_chain_rs2048_proof.bin", "user_sig_rs2048_proof.bin"},
		[]string{"cert_chain_rs2048_verifying.key", "user_sig_rs2048_verifying.key"},
	)
}

func TestLimbConventionMatchesCircuit_RS4096(t *testing.T) {
	runLimbConvention(t, verifier.CertChainRS4096, 4096, issuercert.LimbsRS4096,
		"cc4096_ds2048",
		[]string{"cert_chain_rs4096_proof.bin", "user_sig_rs2048_proof.bin"},
		[]string{"cert_chain_rs4096_verifying.key", "user_sig_rs2048_verifying.key"},
	)
}

func runLimbConvention(t *testing.T, ct verifier.CertChainType, expectedBits, expectedLimbs int, artifactDir string, proofFiles, vkFiles []string) {
	t.Helper()

	keysDir := os.Getenv("KEYS_DIR")
	if keysDir == "" {
		keysDir = filepath.Join("..", "keys")
	}
	absKeysDir, err := filepath.Abs(keysDir)
	if err != nil {
		t.Fatalf("abs keys dir: %v", err)
	}
	for _, name := range vkFiles {
		if _, err := os.Stat(filepath.Join(absKeysDir, name)); err != nil {
			t.Fatalf("verifying key missing at %s (run make download-keys)", filepath.Join(absKeysDir, name))
		}
	}
	artifactsDir := filepath.Join("..", "tests", "artifacts", artifactDir)

	tmpDir := t.TempDir()
	tmpKeys := filepath.Join(tmpDir, "keys")
	if err := os.Mkdir(tmpKeys, 0o755); err != nil {
		t.Fatalf("mkdir keys: %v", err)
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
		src := filepath.Join(absKeysDir, name)
		dst := filepath.Join(tmpKeys, name)
		if err := os.Symlink(src, dst); err != nil {
			t.Fatalf("symlink vk: %v", err)
		}
	}

	ok, signals, err := verifier.LinkVerify(tmpDir, ct)
	if err != nil {
		t.Fatalf("LinkVerify: %v", err)
	}
	if !ok {
		t.Fatal("LinkVerify returned false")
	}
	parsed, err := verifier.ParsePublicInputs(signals, ct)
	if err != nil {
		t.Fatalf("ParsePublicInputs: %v", err)
	}

	if got := len(parsed.IssuerRSAModulus); got != expectedLimbs {
		t.Fatalf("limb count: got %d, want %d", got, expectedLimbs)
	}

	n := new(big.Int)
	limb := new(big.Int)
	for i := len(parsed.IssuerRSAModulus) - 1; i >= 0; i-- {
		h := strings.TrimPrefix(parsed.IssuerRSAModulus[i], "0x")
		if _, ok := limb.SetString(h, 16); !ok {
			t.Fatalf("limb[%d] not hex: %s", i, parsed.IssuerRSAModulus[i])
		}
		if limb.BitLen() > issuercert.LimbBits {
			t.Errorf("limb[%d] overflows %d bits: %d", i, issuercert.LimbBits, limb.BitLen())
		}
		n.Lsh(n, issuercert.LimbBits)
		n.Add(n, limb)
	}
	if bits := n.BitLen(); bits != expectedBits {
		t.Fatalf("recomposed modulus: %d bits, want %d — limb convention drift", bits, expectedBits)
	}
	if n.Bit(0) != 1 {
		t.Error("recomposed modulus is even — not a valid RSA N")
	}

	reencoded := issuercert.ModulusToLimbs(n, expectedLimbs)
	if !issuercert.LimbsEqual(reencoded, parsed.IssuerRSAModulus) {
		t.Fatalf("re-encoded limbs do not match original")
	}
	t.Logf("%d-bit modulus round-trip OK (first limb=%s, last limb=%s)",
		expectedBits, parsed.IssuerRSAModulus[0], parsed.IssuerRSAModulus[len(parsed.IssuerRSAModulus)-1])
}
