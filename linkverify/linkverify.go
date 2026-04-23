package linkverify

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/zkmopro/go-zkid-verifier/verifier"
)

// PublicSignals is an alias for the verifier public signals type.
type PublicSignals = verifier.PublicSignals

// ProofType selects the cert-chain RSA key size variant.
type ProofType string

const (
	ProofTypeRS2048 ProofType = "rs2048" // cert_chain_rs2048 + device_sig_rs2048
	ProofTypeRS4096 ProofType = "rs4096" // cert_chain_rs4096 + device_sig_rs2048
)

// ParseProofType validates cert_chain_type. An empty string defaults to RS2048.
func ParseProofType(s string) (ProofType, error) {
	switch s {
	case "", string(ProofTypeRS2048):
		return ProofTypeRS2048, nil
	case string(ProofTypeRS4096):
		return ProofTypeRS4096, nil
	default:
		return "", fmt.Errorf("invalid cert_chain_type: must be %q or %q", ProofTypeRS2048, ProofTypeRS4096)
	}
}

// StoreKey is the string recorded in the verifications.proof_type column.
func (pt ProofType) StoreKey() string {
	if pt == ProofTypeRS4096 {
		return "link_rs4096"
	}
	return "link_rs2048"
}

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

// Verify runs link verification with the configured proof type.
func Verify(req Request, keysDir string) (bool, *PublicSignals, error) {
	verifySem <- struct{}{}
	defer func() { <-verifySem }()

	pt := req.ProofType
	if pt == "" {
		pt = ProofTypeRS2048
	}

	ccProofName, dsProofName, ccVKName, dsVKName := proofFileNames(pt)

	tmpDir, err := os.MkdirTemp("", "zkid-linkverify-*")
	if err != nil {
		return false, nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	tmpKeys := filepath.Join(tmpDir, "keys")
	if err := os.Mkdir(tmpKeys, 0o755); err != nil {
		return false, nil, fmt.Errorf("create temp keys dir: %w", err)
	}

	if err := os.WriteFile(filepath.Join(tmpKeys, ccProofName), req.CertChainProof, 0o600); err != nil {
		return false, nil, fmt.Errorf("write cert-chain proof: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tmpKeys, dsProofName), req.DeviceSigProof, 0o600); err != nil {
		return false, nil, fmt.Errorf("write device-sig proof: %w", err)
	}

	for _, vk := range []string{ccVKName, dsVKName} {
		src := filepath.Join(keysDir, vk)
		dst := filepath.Join(tmpKeys, vk)
		if err := os.Symlink(src, dst); err != nil {
			return false, nil, fmt.Errorf("symlink %s: %w", vk, err)
		}
	}

	certChainType := verifier.CertChainRS2048
	if pt == ProofTypeRS4096 {
		certChainType = verifier.CertChainRS4096
	}

	return verifier.LinkVerify(tmpDir, certChainType)
}
