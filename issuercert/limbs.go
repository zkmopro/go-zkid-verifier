package issuercert

import (
	"encoding/hex"
	"math/big"
	"strings"
)

const (
	LimbBits    = 121
	LimbsRS2048 = 17
	LimbsRS4096 = 34
)

// ModulusToLimbs converts n into k little-endian 121-bit hex limbs.
func ModulusToLimbs(n *big.Int, k int) []string {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), LimbBits), big.NewInt(1))
	out := make([]string, k)
	tmp := new(big.Int)
	var buf [32]byte
	for i := 0; i < k; i++ {
		tmp.Rsh(n, uint(i*LimbBits))
		tmp.And(tmp, mask)
		tmp.FillBytes(buf[:])
		out[i] = "0x" + hex.EncodeToString(buf[:])
	}
	return out
}

// LimbsEqual compares two limb slices after hex normalization.
func LimbsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if normHex(a[i]) != normHex(b[i]) {
			return false
		}
	}
	return true
}

func normHex(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	s = strings.ToLower(s)
	if len(s) < 64 {
		s = strings.Repeat("0", 64-len(s)) + s
	}
	return s
}
