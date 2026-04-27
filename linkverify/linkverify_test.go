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
	t.Logf("nullifier:          %s", pi.Nullifier)
	t.Logf("app_id:             %s", pi.AppID)
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

// Drives Verify with the configured ExpectedAppID set to the value the prover
// actually emitted (default fixture: app_id=0). Confirms the wire-format hex
// observed in the proof and the bare decimal in env normalize to the same
// big.Int so a default-config deployment doesn't silently reject every proof.
func TestVerifier_AppIDEnforcement(t *testing.T) {
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
	req := Request{
		CertChainProof: ccProof,
		DeviceSigProof: dsProof,
		ProofType:      ProofTypeRS2048,
	}

	matchV := &Verifier{KeysDir: absKeysDir, ExpectedAppID: "0", Logger: smtroot.DefaultLogger{}}
	matchRes, err := matchV.Verify(req)
	if err != nil {
		t.Fatalf("Verify with matching APP_ID: %v", err)
	}
	if !matchRes.Verified {
		t.Fatalf("expected Verified=true with APP_ID=0, got reason=%q", matchRes.Reason)
	}
	if matchRes.AppID == nil || !matchRes.AppID.Match {
		t.Fatalf("expected AppID.Match=true, got %+v", matchRes.AppID)
	}

	mismatchV := &Verifier{KeysDir: absKeysDir, ExpectedAppID: "42", Logger: smtroot.DefaultLogger{}}
	mismatchRes, err := mismatchV.Verify(req)
	if err != nil {
		t.Fatalf("Verify with mismatching APP_ID: %v", err)
	}
	if mismatchRes.Verified {
		t.Fatalf("expected Verified=false with APP_ID=42")
	}
	if mismatchRes.Reason != ReasonAppIDMismatch {
		t.Errorf("Reason = %q, want %q", mismatchRes.Reason, ReasonAppIDMismatch)
	}
	if mismatchRes.AppID == nil || mismatchRes.AppID.Match {
		t.Fatalf("expected AppID.Match=false, got %+v", mismatchRes.AppID)
	}
	if mismatchRes.AppID.Expected != "42" {
		t.Errorf("AppID.Expected = %q, want %q", mismatchRes.AppID.Expected, "42")
	}
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
