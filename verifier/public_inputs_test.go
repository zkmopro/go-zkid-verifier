package verifier

import (
	"encoding/hex"
	"testing"
)

func TestParseDeviceSig(t *testing.T) {
	const pkCommit = "0xdeadbeef"
	const nullifier = "0xfeedface"
	const challenge = "1234567890"

	// Pack 0x01..0x1f (31 bytes) little-endian into a field element.
	bytes := make([]byte, AppIDLen)
	for i := 0; i < AppIDLen; i++ {
		bytes[i] = byte(i + 1)
	}
	packed, err := PackAppIDLE(bytes)
	if err != nil {
		t.Fatalf("PackAppIDLE: %v", err)
	}

	ds, err := ParseDeviceSig([]string{pkCommit, nullifier, packed, challenge})
	if err != nil {
		t.Fatalf("ParseDeviceSig: %v", err)
	}
	if ds.PkCommit != pkCommit {
		t.Errorf("PkCommit: got %s, want %s", ds.PkCommit, pkCommit)
	}
	if ds.Nullifier != nullifier {
		t.Errorf("Nullifier: got %s, want %s", ds.Nullifier, nullifier)
	}
	if ds.AppIDPacked != packed {
		t.Errorf("AppIDPacked: got %s, want %s", ds.AppIDPacked, packed)
	}
	if ds.Challenge != challenge {
		t.Errorf("Challenge: got %s, want %s", ds.Challenge, challenge)
	}
}

func TestParseDeviceSigStrictLength(t *testing.T) {
	if _, err := ParseDeviceSig(make([]string, 3)); err == nil {
		t.Error("expected error for 3 signals (need 4)")
	}
	if _, err := ParseDeviceSig(make([]string, 5)); err == nil {
		t.Error("expected error for 5 signals (need 4)")
	}
}

func TestPackUnpackAppIDRoundTrip(t *testing.T) {
	cases := [][]byte{
		bytesIota(AppIDLen),
		bytesAll(0xff),
		append([]byte{0x00, 0x00}, bytesIota(AppIDLen-2)...),
	}
	for _, b := range cases {
		packed, err := PackAppIDLE(b)
		if err != nil {
			t.Fatalf("PackAppIDLE: %v", err)
		}
		got, err := UnpackAppIDHex(packed)
		if err != nil {
			t.Fatalf("UnpackAppIDHex: %v", err)
		}
		if got != hex.EncodeToString(b) {
			t.Errorf("round-trip mismatch: got %s, want %s", got, hex.EncodeToString(b))
		}
	}
}

func TestUnpackAppIDRejectsOversize(t *testing.T) {
	// 32-byte value (overflows the 31-byte budget for app_id).
	tooBig := "0x" + "01" + repeat("00", 31)
	if _, err := UnpackAppIDHex(tooBig); err == nil {
		t.Error("expected error for >31-byte packed value")
	}
}

func bytesIota(n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = byte(i + 1)
	}
	return out
}

func bytesAll(v byte) []byte {
	out := make([]byte, AppIDLen)
	for i := range out {
		out[i] = v
	}
	return out
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func TestParseCertChainRS2048(t *testing.T) {
	signals := make([]string, 19)
	signals[0] = "0xpk"
	for i := 1; i < 18; i++ {
		signals[i] = "0xlimb"
	}
	signals[18] = "0xroot"

	cc, err := ParseCertChainRS2048(signals)
	if err != nil {
		t.Fatalf("ParseCertChainRS2048: %v", err)
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
}

func TestParseCertChainRS2048StrictLength(t *testing.T) {
	if _, err := ParseCertChainRS2048(make([]string, 18)); err == nil {
		t.Error("expected error for 18 signals (need exactly 19)")
	}
	if _, err := ParseCertChainRS2048(make([]string, 20)); err == nil {
		t.Error("expected error for 20 signals (need exactly 19)")
	}
}

func TestParseCertChainRS4096(t *testing.T) {
	signals := make([]string, 36)
	signals[0] = "0xpk"
	for i := 1; i < 35; i++ {
		signals[i] = "0xlimb"
	}
	signals[35] = "0xroot"

	cc, err := ParseCertChainRS4096(signals)
	if err != nil {
		t.Fatalf("ParseCertChainRS4096: %v", err)
	}
	if cc.PkCommit != "0xpk" {
		t.Errorf("PkCommit: got %q", cc.PkCommit)
	}
	if len(cc.IssuerRSAModulus) != 34 {
		t.Errorf("IssuerRSAModulus length: got %d, want 34", len(cc.IssuerRSAModulus))
	}
	if cc.SmtRoot != "0xroot" {
		t.Errorf("SmtRoot: got %q", cc.SmtRoot)
	}
}

func TestParseCertChainRS4096StrictLength(t *testing.T) {
	if _, err := ParseCertChainRS4096(make([]string, 35)); err == nil {
		t.Error("expected error for 35 signals (need exactly 36)")
	}
	if _, err := ParseCertChainRS4096(make([]string, 37)); err == nil {
		t.Error("expected error for 37 signals (need exactly 36)")
	}
}
