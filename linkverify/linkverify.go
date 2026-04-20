package linkverify

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/zkmopro/go-zkid-verifier/verifier"
)

// ProofType selects the cert-chain RSA key size variant.
type ProofType string

const (
	ProofTypeRS2048 ProofType = "rs2048" // cert_chain_rs2048 + device_sig_rs2048
	ProofTypeRS4096 ProofType = "rs4096" // cert_chain_rs4096 + device_sig_rs2048
)

// maxConcurrent limits parallel ZK verifications to prevent temp dir / CPU exhaustion.
var verifySem = make(chan struct{}, 10)

// Request holds the proof data for a link-verify operation.
type Request struct {
	CertChainProof []byte    // binary proof bytes
	DeviceSigProof []byte    // binary proof bytes
	ProofType      ProofType // "rs2048" or "rs4096"
}

// proofFileNames returns the expected file names for the proof type.
func proofFileNames(pt ProofType) (ccProof, dsProof, ccVK, dsVK string) {
	dsProof = "device_sig_rs2048_proof.bin"
	dsVK = "device_sig_rs2048_verifying.key"
	if pt == ProofTypeRS4096 {
		ccProof = "cert_chain_rs4096_proof.bin"
		ccVK = "cert_chain_rs4096_verifying.key"
	} else {
		ccProof = "cert_chain_rs2048_proof.bin"
		ccVK = "cert_chain_rs2048_verifying.key"
	}
	return
}

// Verify runs link-verify on the provided proofs using verifying keys from keysDir.
//
// It creates a temp directory, writes the proof bytes to it, symlinks the
// verifying keys from keysDir, calls the Rust FFI, and cleans up.
// Concurrent calls are bounded by a semaphore to prevent resource exhaustion.
func Verify(req Request, keysDir string) (bool, error) {
	// Acquire semaphore slot to bound concurrent verifications.
	verifySem <- struct{}{}
	defer func() { <-verifySem }()

	pt := req.ProofType
	if pt == "" {
		pt = ProofTypeRS2048
	}

	ccProofName, dsProofName, ccVKName, dsVKName := proofFileNames(pt)

	// Create temp directory with keys/ subdirectory
	tmpDir, err := os.MkdirTemp("", "zkid-linkverify-*")
	if err != nil {
		return false, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	tmpKeys := filepath.Join(tmpDir, "keys")
	if err := os.Mkdir(tmpKeys, 0o755); err != nil {
		return false, fmt.Errorf("create temp keys dir: %w", err)
	}

	// Write proof bytes with restrictive permissions (user-only read/write).
	if err := os.WriteFile(filepath.Join(tmpKeys, ccProofName), req.CertChainProof, 0o600); err != nil {
		return false, fmt.Errorf("write cert-chain proof: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tmpKeys, dsProofName), req.DeviceSigProof, 0o600); err != nil {
		return false, fmt.Errorf("write device-sig proof: %w", err)
	}

	// Symlink verifying keys from the permanent keys directory
	for _, vk := range []string{ccVKName, dsVKName} {
		src := filepath.Join(keysDir, vk)
		dst := filepath.Join(tmpKeys, vk)
		if err := os.Symlink(src, dst); err != nil {
			return false, fmt.Errorf("symlink %s: %w", vk, err)
		}
	}

	// Call FFI
	certChainType := verifier.CertChainRS2048
	if pt == ProofTypeRS4096 {
		certChainType = verifier.CertChainRS4096
	}

	return verifier.LinkVerify(tmpDir, certChainType)
}
