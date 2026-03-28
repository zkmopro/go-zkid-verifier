package challenge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

const DefaultTTL = 5 * time.Minute

type Challenge struct {
	ID        string    `json:"challenge_id"`
	Bytes     [32]byte  `json:"-"`
	BytesHex  string    `json:"challenge_bytes"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Store struct {
	mu         sync.RWMutex
	challenges map[string]*Challenge
	ttl        time.Duration
}

func NewStore(ttl time.Duration) *Store {
	return &Store{
		challenges: make(map[string]*Challenge),
		ttl:        ttl,
	}
}

func (s *Store) Create() (*Challenge, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	idHash := sha256.Sum256(nonce[:])
	id := hex.EncodeToString(idHash[:16])

	c := &Challenge{
		ID:        id,
		Bytes:     nonce,
		BytesHex:  hex.EncodeToString(nonce[:]),
		ExpiresAt: time.Now().Add(s.ttl),
	}

	s.mu.Lock()
	s.challenges[id] = c
	s.mu.Unlock()

	return c, nil
}

func (s *Store) Get(id string) (*Challenge, bool) {
	s.mu.RLock()
	c, ok := s.challenges[id]
	s.mu.RUnlock()

	if !ok {
		return nil, false
	}
	if time.Now().After(c.ExpiresAt) {
		s.mu.Lock()
		delete(s.challenges, id)
		s.mu.Unlock()
		return nil, false
	}
	return c, true
}

// TBSHashBitsFromChallenge computes SHA256(challenge_bytes) and returns
// 256 big-endian bits matching the circuit's tbs_hash output format.
func TBSHashBitsFromChallenge(challengeBytes [32]byte) [256]int {
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
func VerifyTBSHash(challengeBytes [32]byte, tbsHashBits []int) bool {
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
