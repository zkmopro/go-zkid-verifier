package verifier

import "testing"

// packedTBS is the field element for the 31-byte challenge "e775f2805fb993e05a208dbff15d1c1"
// packed little-endian and serialised as big-endian hex by field_to_hex.
const packedTBS = "0x0031633164353166666264383032613530653339396266353038326635373765"

func TestParseDeviceSig(t *testing.T) {
	const pkCommit = "0xdeadbeef"
	signals := []string{pkCommit, packedTBS}

	ds, err := ParseDeviceSig(signals)
	if err != nil {
		t.Fatalf("ParseDeviceSig: %v", err)
	}
	if ds.PkCommit != pkCommit {
		t.Errorf("PkCommit: got %s, want %s", ds.PkCommit, pkCommit)
	}
	if ds.PackedTBS != packedTBS {
		t.Errorf("PackedTBS: got %s, want %s", ds.PackedTBS, packedTBS)
	}

	challenge, err := ds.Challenge()
	if err != nil {
		t.Fatalf("Challenge(): %v", err)
	}
	const want = "e775f2805fb993e05a208dbff15d1c1"
	if challenge != want {
		t.Errorf("Challenge(): got %q, want %q", challenge, want)
	}
}

func TestParseDeviceSigTooFewSignals(t *testing.T) {
	if _, err := ParseDeviceSig([]string{"only_one"}); err == nil {
		t.Error("expected error for fewer than 2 signals")
	}
}

func TestParseCertChainRS2048(t *testing.T) {
	signals := make([]string, 21)
	signals[0] = "0xnullifier"
	signals[1] = "0xpk"
	for i := 2; i < 19; i++ {
		signals[i] = "0xlimb"
	}
	signals[19] = "0xroot"
	signals[20] = "0xappid"

	cc, err := ParseCertChainRS2048(signals)
	if err != nil {
		t.Fatalf("ParseCertChainRS2048: %v", err)
	}
	if cc.Nullifier != "0xnullifier" {
		t.Errorf("Nullifier: got %q", cc.Nullifier)
	}
	if cc.PkCommit != "0xpk" {
		t.Errorf("PkCommit: got %q", cc.PkCommit)
	}
	if len(cc.IssuerRSAModulus) != 17 {
		t.Errorf("IssuerRSAModulus length: got %d, want 17", len(cc.IssuerRSAModulus))
	}
	if cc.SmtRoot != "0xroot" {
		t.Errorf("SmtRoot: got %q", cc.SmtRoot)
	}
	if cc.AppID != "0xappid" {
		t.Errorf("AppID: got %q", cc.AppID)
	}
}

func TestParseCertChainRS2048StrictLength(t *testing.T) {
	if _, err := ParseCertChainRS2048(make([]string, 20)); err == nil {
		t.Error("expected error for 20 signals (need exactly 21)")
	}
	if _, err := ParseCertChainRS2048(make([]string, 22)); err == nil {
		t.Error("expected error for 22 signals (need exactly 21)")
	}
}

func TestParseCertChainRS4096(t *testing.T) {
	signals := make([]string, 38)
	signals[0] = "0xnullifier"
	signals[1] = "0xpk"
	for i := 2; i < 36; i++ {
		signals[i] = "0xlimb"
	}
	signals[36] = "0xroot"
	signals[37] = "0xappid"

	cc, err := ParseCertChainRS4096(signals)
	if err != nil {
		t.Fatalf("ParseCertChainRS4096: %v", err)
	}
	if cc.Nullifier != "0xnullifier" {
		t.Errorf("Nullifier: got %q", cc.Nullifier)
	}
	if len(cc.IssuerRSAModulus) != 34 {
		t.Errorf("IssuerRSAModulus length: got %d, want 34", len(cc.IssuerRSAModulus))
	}
	if cc.SmtRoot != "0xroot" {
		t.Errorf("SmtRoot: got %q", cc.SmtRoot)
	}
	if cc.AppID != "0xappid" {
		t.Errorf("AppID: got %q", cc.AppID)
	}
}

func TestParseCertChainRS4096StrictLength(t *testing.T) {
	if _, err := ParseCertChainRS4096(make([]string, 37)); err == nil {
		t.Error("expected error for 37 signals (need exactly 38)")
	}
	if _, err := ParseCertChainRS4096(make([]string, 39)); err == nil {
		t.Error("expected error for 39 signals (need exactly 38)")
	}
}
