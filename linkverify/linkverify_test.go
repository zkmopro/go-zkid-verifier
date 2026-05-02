package linkverify

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zkmopro/go-zkid-verifier/issuercert"
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

// loadArtifactSignals runs the FFI verifier against fixtures in artifactsDir
// and returns the raw public signals. Skips if verifying keys are absent.
func loadArtifactSignals(t *testing.T, artifactsDir, ccFile, dsFile string, pt ProofType, keyFile string) *PublicSignals {
	t.Helper()
	keysDir := resolveKeysDir(t)
	if keysDir == "" {
		t.Skipf("verifying keys not found (missing %s); set KEYS_DIR or run make download-keys", keyFile)
	}
	ccProof, err := os.ReadFile(filepath.Join(artifactsDir, ccFile))
	if err != nil {
		t.Fatalf("read %s: %v", ccFile, err)
	}
	dsProof, err := os.ReadFile(filepath.Join(artifactsDir, dsFile))
	if err != nil {
		t.Fatalf("read %s: %v", dsFile, err)
	}
	valid, signals, err := Verify(Request{CertChainProof: ccProof, DeviceSigProof: dsProof, ProofType: pt}, keysDir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !valid {
		t.Fatal("expected proof to be valid")
	}
	return signals
}

// TestArtifactIssuerCert_CC2048_LimbCount verifies that the cc2048_ds2048 fixture
// produces exactly 17 issuer-modulus limbs, confirming the proof is routed to
// IssuerG2 (RS2048). Fixtures use mock certificates, so limb values are not
// compared against the embedded MOICA certs — asserted explicitly below.
func TestArtifactIssuerCert_CC2048_LimbCount(t *testing.T) {
	dir := filepath.Join("..", "tests", "artifacts", "cc2048_ds2048")
	signals := loadArtifactSignals(t, dir, "cert_chain_rs2048_proof.bin", "device_sig_rs2048_proof.bin",
		ProofTypeRS2048, "cert_chain_rs2048_verifying.key")

	pi, err := verifier.ParseCertChainRS2048(signals.CertChain)
	if err != nil {
		t.Fatalf("ParseCertChainRS2048: %v", err)
	}
	if got := len(pi.IssuerRSAModulus); got != issuercert.LimbsRS2048 {
		t.Fatalf("issuer modulus limb count: got %d, want %d (RS2048/G2)", got, issuercert.LimbsRS2048)
	}

	// Fixtures are intentionally mock — must NOT match any embedded MOICA cert.
	certs, err := issuercert.LoadEmbedded(time.Now())
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if issuercert.LimbsEqual(certs[issuercert.IssuerG2].Limbs, pi.IssuerRSAModulus) {
		t.Error("fixture must not match real MOICA-G2 — regenerate fixtures with mock certs")
	}
	if issuercert.LimbsEqual(certs[issuercert.IssuerG3].Limbs, pi.IssuerRSAModulus) {
		t.Error("fixture must not match real MOICA-G3 — regenerate fixtures with mock certs")
	}
}

// TestArtifactIssuerCert_CC4096_LimbCount verifies that the cc4096_ds2048 fixture
// produces exactly 34 issuer-modulus limbs, confirming the proof is routed to
// IssuerG3 (RS4096). Fixtures use mock certificates, so limb values are not
// compared against the embedded MOICA certs — asserted explicitly below.
func TestArtifactIssuerCert_CC4096_LimbCount(t *testing.T) {
	dir := filepath.Join("..", "tests", "artifacts", "cc4096_ds2048")
	signals := loadArtifactSignals(t, dir, "cert_chain_rs4096_proof.bin", "device_sig_rs2048_proof.bin",
		ProofTypeRS4096, "cert_chain_rs4096_verifying.key")

	pi, err := verifier.ParseCertChainRS4096(signals.CertChain)
	if err != nil {
		t.Fatalf("ParseCertChainRS4096: %v", err)
	}
	if got := len(pi.IssuerRSAModulus); got != issuercert.LimbsRS4096 {
		t.Fatalf("issuer modulus limb count: got %d, want %d (RS4096/G3)", got, issuercert.LimbsRS4096)
	}

	// Fixtures are intentionally mock — must NOT match any embedded MOICA cert.
	certs, err := issuercert.LoadEmbedded(time.Now())
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if issuercert.LimbsEqual(certs[issuercert.IssuerG3].Limbs, pi.IssuerRSAModulus) {
		t.Error("fixture must not match real MOICA-G3 — regenerate fixtures with mock certs")
	}
	if issuercert.LimbsEqual(certs[issuercert.IssuerG2].Limbs, pi.IssuerRSAModulus) {
		t.Error("fixture must not match real MOICA-G2 — regenerate fixtures with mock certs")
	}
}

// TestRealArtifactIssuerCert_CC4096_IsG3Family verifies that the
// real_cc4096_ds2048 proof embeds exactly 34 issuer-modulus limbs, proving
// the circuit routed to a 4096-bit (G3-family) issuer.
//
// The exact modulus value is NOT compared against the embedded MOICA-G3 cert
// because the proof was generated against an earlier version of the cert (MOICA-G3
// is renewed periodically by the Taiwanese government). Regenerate
// tests/artifacts/real_cc4096_ds2048/ against the current MOICA-G3 to add an
// exact-match assertion.
func TestRealArtifactIssuerCert_CC4096_IsG3Family(t *testing.T) {
	dir := filepath.Join("..", "tests", "artifacts", "real_cc4096_ds2048")
	signals := loadArtifactSignals(t, dir, "cert_chain_rs4096_proof.bin", "device_sig_rs2048_proof.bin",
		ProofTypeRS4096, "cert_chain_rs4096_verifying.key")

	pi, err := verifier.ParseCertChainRS4096(signals.CertChain)
	if err != nil {
		t.Fatalf("ParseCertChainRS4096: %v", err)
	}
	if got := len(pi.IssuerRSAModulus); got != issuercert.LimbsRS4096 {
		t.Fatalf("issuer modulus limb count: got %d, want %d (RS4096/G3)", got, issuercert.LimbsRS4096)
	}

	certs, err := issuercert.LoadEmbedded(time.Now())
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	// Must not match a 2048-bit G2 cert — that would indicate a routing bug.
	if issuercert.LimbsEqual(certs[issuercert.IssuerG2].Limbs, pi.IssuerRSAModulus) {
		t.Error("issuer modulus limbs must not match MOICA-G2 (routing bug)")
	}
	// Log whether the proof matches the currently embedded G3 cert for diagnostics.
	if issuercert.LimbsEqual(certs[issuercert.IssuerG3].Limbs, pi.IssuerRSAModulus) {
		t.Logf("proof modulus matches currently embedded MOICA-G3 (%s)", certs[issuercert.IssuerG3].SHA256Hex)
	} else {
		t.Logf("proof modulus does not match embedded MOICA-G3 (%s) — proof was generated with an older cert version; regenerate artifacts to restore exact-match coverage", certs[issuercert.IssuerG3].SHA256Hex)
	}
}

// TestRealArtifactIssuerCert_CC2048_IsG2Family verifies that the
// real_cc2048_ds2048 proof embeds exactly 17 issuer-modulus limbs, proving
// the circuit routed to a 2048-bit (G2-family) issuer.
//
// The exact modulus value is NOT compared against the embedded MOICA-G2 cert
// because the proof may have been generated against an earlier cert version.
// Regenerate tests/artifacts/real_cc2048_ds2048/ against the current MOICA-G2
// to add an exact-match assertion.
func TestRealArtifactIssuerCert_CC2048_IsG2Family(t *testing.T) {
	dir := filepath.Join("..", "tests", "artifacts", "real_cc2048_ds2048")
	signals := loadArtifactSignals(t, dir, "cert_chain_rs2048_proof.bin", "device_sig_rs2048_proof.bin",
		ProofTypeRS2048, "cert_chain_rs2048_verifying.key")

	pi, err := verifier.ParseCertChainRS2048(signals.CertChain)
	if err != nil {
		t.Fatalf("ParseCertChainRS2048: %v", err)
	}
	if got := len(pi.IssuerRSAModulus); got != issuercert.LimbsRS2048 {
		t.Fatalf("issuer modulus limb count: got %d, want %d (RS2048/G2)", got, issuercert.LimbsRS2048)
	}

	certs, err := issuercert.LoadEmbedded(time.Now())
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	// Must not match a 4096-bit G3 cert — that would indicate a routing bug.
	if issuercert.LimbsEqual(certs[issuercert.IssuerG3].Limbs, pi.IssuerRSAModulus) {
		t.Error("issuer modulus limbs must not match MOICA-G3 (routing bug)")
	}
	// Log whether the proof matches the currently embedded G2 cert for diagnostics.
	if issuercert.LimbsEqual(certs[issuercert.IssuerG2].Limbs, pi.IssuerRSAModulus) {
		t.Logf("proof modulus matches currently embedded MOICA-G2 (%s)", certs[issuercert.IssuerG2].SHA256Hex)
	} else {
		t.Logf("proof modulus does not match embedded MOICA-G2 (%s) — proof was generated with an older cert version; regenerate artifacts to restore exact-match coverage", certs[issuercert.IssuerG2].SHA256Hex)
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
