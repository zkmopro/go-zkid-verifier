package issuercert

import (
	"testing"
	"time"
)

func TestLoadEmbedded(t *testing.T) {
	// Use a fixed time within the validity windows of all four certs.
	// MOICA-G2: 2014-01-02 → 2034-01-02. MOICA-G3: 2024-01-23 → 2044-01-23.
	// GRCA-G2: 2012 → 2037. GRCA-G3: 2022 → 2049.
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	records, err := LoadEmbedded(now)
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	for _, id := range []IssuerID{IssuerG2, IssuerG3} {
		rec, ok := records[id]
		if !ok {
			t.Fatalf("no record for %s", id.LongName())
		}
		if rec.Source != "embedded" {
			t.Errorf("%s source: got %q, want \"embedded\"", id.LongName(), rec.Source)
		}
		if rec.PubKey == nil || rec.PubKey.N == nil {
			t.Fatalf("%s missing RSA modulus", id.LongName())
		}
		wantBits := 2048
		wantLimbs := LimbsRS2048
		if id == IssuerG3 {
			wantBits = 4096
			wantLimbs = LimbsRS4096
		}
		if rec.PubKey.N.BitLen() != wantBits {
			t.Errorf("%s modulus: got %d bits, want %d", id.LongName(), rec.PubKey.N.BitLen(), wantBits)
		}
		if len(rec.Limbs) != wantLimbs {
			t.Errorf("%s limbs: got %d, want %d", id.LongName(), len(rec.Limbs), wantLimbs)
		}
	}
}

func TestLoadEmbedded_ExpiredAtFutureDate(t *testing.T) {
	// Far past MOICA-G2's NotAfter (2034-01-02). Load must fail — LoadEmbedded
	// is a trust-anchor bootstrap that must not accept expired CAs.
	future := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := LoadEmbedded(future); err == nil {
		t.Fatal("LoadEmbedded at 2099: expected error, got nil")
	}
}

func TestLoadEmbedded_BeforeMoicaG3(t *testing.T) {
	// Before MOICA-G3's NotBefore (2024-01-23), G3 load should fail but G2
	// should still be valid. LoadEmbedded is all-or-nothing, so this also
	// fails overall — confirming the loud-failure posture.
	before := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := LoadEmbedded(before); err == nil {
		t.Fatal("LoadEmbedded at 2023: expected error for G3, got nil")
	}
}
