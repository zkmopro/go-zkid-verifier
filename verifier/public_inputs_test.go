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
