package verifier

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
)

// CertChainRS4096PublicInputs holds the named public outputs from the cert-chain RS4096 circuit.
//
// Layout (38 field elements):
//
//	0:     subject_dn_hash
//	1:     pk_commit
//	2–35:  issuer_rsa_modulus  (34 limbs)
//	36:    smt_root
//	37:    serial_number
type CertChainRS4096PublicInputs struct {
	SubjectDNHash    string
	PkCommit         string
	IssuerRSAModulus []string // 34 limbs
	SmtRoot          string
	SerialNumber     string
}

// ParseCertChainRS4096 parses the raw CertChain signal slice from PublicSignals
// into named fields. Returns an error if the slice has fewer than 38 elements.
func ParseCertChainRS4096(signals []string) (*CertChainRS4096PublicInputs, error) {
	const required = 38
	if len(signals) < required {
		return nil, fmt.Errorf("cert_chain RS4096 requires %d public inputs, got %d", required, len(signals))
	}
	return &CertChainRS4096PublicInputs{
		SubjectDNHash:    signals[0],
		PkCommit:         signals[1],
		IssuerRSAModulus: signals[2:36],
		SmtRoot:          signals[36],
		SerialNumber:     signals[37],
	}, nil
}

// DeviceSigPublicInputs holds the named public outputs from the device-sig circuit.
//
// Layout:
//
//	0:  pk_commit
//	1:  packed_tbs  (tbs_hex bytes packed 31 bytes per field element, single field element)
type DeviceSigPublicInputs struct {
	PkCommit  string
	PackedTBS string
}

// ParseDeviceSig parses the raw DeviceSig signal slice into named fields.
func ParseDeviceSig(signals []string) (*DeviceSigPublicInputs, error) {
	if len(signals) < 2 {
		return nil, fmt.Errorf("device_sig requires at least 2 public inputs, got %d", len(signals))
	}
	return &DeviceSigPublicInputs{
		PkCommit:  signals[0],
		PackedTBS: signals[1],
	}, nil
}

// Challenge unpacks PackedTBS and returns the original challenge string.
//
// The packed TBS is a SHA-256 padded message: challenge ASCII bytes followed by
// a 0x80 padding marker. Everything from 0x80 onwards is discarded.
func (d *DeviceSigPublicInputs) Challenge() (string, error) {
	b, err := UnpackBytes([]string{d.PackedTBS})
	if err != nil {
		return "", err
	}
	// SHA-256 padding starts with 0x80; challenge bytes precede it.
	if i := bytes.IndexByte(b, 0x80); i >= 0 {
		b = b[:i]
	}
	return string(b), nil
}

// UnpackBytes reverses the JS packBytes function:
//
//	packBytes packs inputBytes 31 bytes per field element as a little-endian integer:
//	  acc = b[0]*1 + b[1]*256 + … + b[30]*256^30
//
// Each field element hex string (big-endian, 0x-prefixed, 32 bytes) decodes as:
//
//	[b[0], b[1], …, b[30], 0x00]
//
// UnpackBytes concatenates the 31 data bytes from each element and trims
// trailing null padding.
func UnpackBytes(packedHex []string) ([]byte, error) {
	const bytesPerField = 31
	out := make([]byte, 0, len(packedHex)*bytesPerField)

	for _, h := range packedHex {
		h = strings.TrimPrefix(h, "0x")
		if len(h) < 64 {
			h = strings.Repeat("0", 64-len(h)) + h
		}
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("decode hex %q: %w", h, err)
		}
		out = append(out, b[:bytesPerField]...)
	}

	return bytes.TrimRight(out, "\x00"), nil
}
