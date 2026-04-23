package issuercert

import (
	"math/big"
	"strings"
	"testing"
)

func TestModulusToLimbs(t *testing.T) {
	cases := []struct {
		name string
		n    *big.Int
		k    int
		want []string
	}{
		{
			name: "zero",
			n:    big.NewInt(0),
			k:    1,
			want: []string{"0x" + strings.Repeat("0", 64)},
		},
		{
			name: "one_fits_in_limb0",
			n:    big.NewInt(1),
			k:    2,
			want: []string{
				"0x" + strings.Repeat("0", 63) + "1",
				"0x" + strings.Repeat("0", 64),
			},
		},
		{
			name: "limb0_max_121_bits",
			n:    new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), LimbBits), big.NewInt(1)),
			k:    2,
			want: []string{
				"0x" + strings.Repeat("0", 33) + "1" + strings.Repeat("f", 30),
				"0x" + strings.Repeat("0", 64),
			},
		},
		{
			name: "carry_to_limb1",
			n:    new(big.Int).Lsh(big.NewInt(1), LimbBits),
			k:    2,
			want: []string{
				"0x" + strings.Repeat("0", 64),
				"0x" + strings.Repeat("0", 63) + "1",
			},
		},
		{
			name: "three_at_limb1_plus_five_at_limb0",
			n: new(big.Int).Add(
				new(big.Int).Lsh(big.NewInt(3), LimbBits),
				big.NewInt(5),
			),
			k: 2,
			want: []string{
				"0x" + strings.Repeat("0", 63) + "5",
				"0x" + strings.Repeat("0", 63) + "3",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ModulusToLimbs(tc.n, tc.k)
			if len(got) != len(tc.want) {
				t.Fatalf("len: got %d, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("limb[%d]: got %s, want %s", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestModulusToLimbs_RoundTrip2048(t *testing.T) {
	// N = (1 << 2047) | 1 — bit set at position 2047 and position 0.
	n := new(big.Int).Or(new(big.Int).Lsh(big.NewInt(1), 2047), big.NewInt(1))
	limbs := ModulusToLimbs(n, LimbsRS2048)
	if len(limbs) != LimbsRS2048 {
		t.Fatalf("len: got %d, want %d", len(limbs), LimbsRS2048)
	}

	// Rebuild N from the limbs and confirm.
	rebuilt := new(big.Int)
	limb := new(big.Int)
	for i := LimbsRS2048 - 1; i >= 0; i-- {
		hex := strings.TrimPrefix(limbs[i], "0x")
		if _, ok := limb.SetString(hex, 16); !ok {
			t.Fatalf("limb[%d] not hex: %s", i, limbs[i])
		}
		rebuilt.Lsh(rebuilt, LimbBits)
		rebuilt.Add(rebuilt, limb)
	}
	if rebuilt.Cmp(n) != 0 {
		t.Errorf("round-trip mismatch: got %x, want %x", rebuilt, n)
	}
}

func TestModulusToLimbs_RoundTrip4096(t *testing.T) {
	// Pseudo-random-ish 4096-bit value: alternating bytes.
	buf := make([]byte, 512)
	for i := range buf {
		if i%2 == 0 {
			buf[i] = 0xa5
		} else {
			buf[i] = 0x5a
		}
	}
	buf[0] |= 0x80 // force MSB so BitLen == 4096
	n := new(big.Int).SetBytes(buf)
	if n.BitLen() != 4096 {
		t.Fatalf("setup: bit length %d, want 4096", n.BitLen())
	}
	limbs := ModulusToLimbs(n, LimbsRS4096)

	rebuilt := new(big.Int)
	limb := new(big.Int)
	for i := LimbsRS4096 - 1; i >= 0; i-- {
		hex := strings.TrimPrefix(limbs[i], "0x")
		if _, ok := limb.SetString(hex, 16); !ok {
			t.Fatalf("limb[%d] not hex: %s", i, limbs[i])
		}
		rebuilt.Lsh(rebuilt, LimbBits)
		rebuilt.Add(rebuilt, limb)
	}
	if rebuilt.Cmp(n) != 0 {
		t.Errorf("round-trip mismatch")
	}
}

func TestModulusToLimbs_EachLimbFitsIn121Bits(t *testing.T) {
	// Modulus with all bits set in its declared width — the only limb allowed
	// to exceed 121 bits would signal a masking bug.
	n := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 2048), big.NewInt(1))
	limbs := ModulusToLimbs(n, LimbsRS2048)
	limb := new(big.Int)
	for i, s := range limbs {
		hex := strings.TrimPrefix(s, "0x")
		if _, ok := limb.SetString(hex, 16); !ok {
			t.Fatalf("limb[%d] not hex: %s", i, s)
		}
		if limb.BitLen() > LimbBits {
			t.Errorf("limb[%d] has %d bits, exceeds %d", i, limb.BitLen(), LimbBits)
		}
	}
}

func TestLimbsEqual(t *testing.T) {
	canonical := "0x" + strings.Repeat("0", 63) + "1"
	cases := []struct {
		name string
		a, b []string
		want bool
	}{
		{"identical", []string{canonical}, []string{canonical}, true},
		{"no_prefix_vs_prefix", []string{"1"}, []string{canonical}, true},
		{"uppercase_hex", []string{"0x0000000000000000000000000000000000000000000000000000000000000001"}, []string{"0X0000000000000000000000000000000000000000000000000000000000000001"}, true},
		{"mixed_case", []string{"0xAbCd"}, []string{"0xabcd"}, true},
		{"different_length_slices", []string{canonical}, []string{canonical, canonical}, false},
		{"different_value", []string{"0x01"}, []string{"0x02"}, false},
		{"whitespace_tolerated", []string{"  0x1  "}, []string{"0x1"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := LimbsEqual(tc.a, tc.b); got != tc.want {
				t.Errorf("LimbsEqual: got %v, want %v", got, tc.want)
			}
		})
	}
}
