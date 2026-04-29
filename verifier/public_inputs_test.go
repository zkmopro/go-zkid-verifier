package verifier

import (
	"fmt"
	"strings"
	"testing"
)

// Mimics the Spartan2 FFI wire format: 0x + 64-char zero-padded big-endian.
func fieldHex(v uint8) string {
	return "0x" + strings.Repeat("0", 62) + fmt.Sprintf("%02x", v)
}

func TestParseDeviceSig(t *testing.T) {
	const pkCommit = "0xdeadbeef"
	const nullifier = "0xfeedface"

	signals := make([]string, 2+AppIDLen)
	signals[0] = pkCommit
	signals[1] = nullifier
	for i := 0; i < AppIDLen; i++ {
		signals[2+i] = fieldHex(uint8(i + 1))
	}

	ds, err := ParseDeviceSig(signals)
	if err != nil {
		t.Fatalf("ParseDeviceSig: %v", err)
	}
	if ds.PkCommit != pkCommit {
		t.Errorf("PkCommit: got %s, want %s", ds.PkCommit, pkCommit)
	}
	if ds.Nullifier != nullifier {
		t.Errorf("Nullifier: got %s, want %s", ds.Nullifier, nullifier)
	}
	wantHex := ""
	for i := 0; i < AppIDLen; i++ {
		wantHex += fmt.Sprintf("%02x", i+1)
	}
	if ds.AppIDHex != wantHex {
		t.Errorf("AppIDHex: got %q, want %q", ds.AppIDHex, wantHex)
	}
}

func TestParseDeviceSigStrictLength(t *testing.T) {
	if _, err := ParseDeviceSig(make([]string, 2)); err == nil {
		t.Error("expected error for 2 signals (need 33)")
	}
	if _, err := ParseDeviceSig(make([]string, 34)); err == nil {
		t.Error("expected error for 34 signals (need 33)")
	}
}

func TestParseDeviceSigRejectsOutOfRangeAppIDByte(t *testing.T) {
	signals := make([]string, 2+AppIDLen)
	signals[0] = "0x01"
	signals[1] = "0x02"
	for i := 0; i < AppIDLen; i++ {
		signals[2+i] = "0x00"
	}
	signals[10] = "0x100" // 256, out of byte range
	if _, err := ParseDeviceSig(signals); err == nil {
		t.Error("expected error for app_id byte > 255")
	}
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
