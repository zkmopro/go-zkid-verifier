package challenge

import (
	"crypto/sha256"
	"time"
)

const DefaultTTL = 5 * time.Minute

// TBSHashBitsFromChallenge computes SHA256(challenge_bytes) and returns
// 256 big-endian bits matching the circuit's tbs_hash output format.
func TBSHashBitsFromChallenge(challengeBytes [16]byte) [256]int {
	digest := sha256.Sum256(challengeBytes[:])
	var bits [256]int
	for i := 0; i < 32; i++ {
		for j := 0; j < 8; j++ {
			// Big-endian: bit 0 = MSB of first byte
			bits[i*8+j] = int((digest[i] >> (7 - j)) & 1)
		}
	}
	return bits
}

// VerifyTBSHash checks if the provided tbs_hash_bits match SHA256(challenge_bytes).
func VerifyTBSHash(challengeBytes [16]byte, tbsHashBits []int) bool {
	if len(tbsHashBits) != 256 {
		return false
	}
	expected := TBSHashBitsFromChallenge(challengeBytes)
	for i := 0; i < 256; i++ {
		if tbsHashBits[i] != expected[i] {
			return false
		}
	}
	return true
}
