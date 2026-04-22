package verifier

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
)

// CertChainRS2048PublicInputs holds the named public outputs from the cert-chain RS2048 circuit.
//
// Layout (21 field elements):
//
//	0:     subject_dn_hash
//	1:     pk_commit
//	2–18:  issuer_rsa_modulus  (17 limbs)
//	19:    smt_root
//	20:    serial_number
type CertChainRS2048PublicInputs struct {
	SubjectDNHash    string
	PkCommit         string
	IssuerRSAModulus []string // 17 limbs
	SmtRoot          string
	SerialNumber     string
}

// ParseCertChainRS2048 parses the raw CertChain signal slice from PublicSignals
// into named fields. Returns an error if the slice has fewer than 21 elements.
func ParseCertChainRS2048(signals []string) (*CertChainRS2048PublicInputs, error) {
	const required = 21
	if len(signals) < required {
		return nil, fmt.Errorf("cert_chain RS2048 requires %d public inputs, got %d", required, len(signals))
	}
	return &CertChainRS2048PublicInputs{
		SubjectDNHash:    signals[0],
		PkCommit:         signals[1],
		IssuerRSAModulus: signals[2:19],
		SmtRoot:          signals[19],
		SerialNumber:     signals[20],
	}, nil
}

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
// field_to_hex serialises the field element as big-endian hex (32 bytes):
//
//	[0x00, b[30], b[29], …, b[1], b[0]]
//
// UnpackBytes reverses each 32-byte block back to little-endian, extracts the
// 31 data bytes [b[0]…b[30]], concatenates them, and trims trailing null padding.
func UnpackBytes(packedHex []string) ([]byte, error) {
	const fieldBytes = 32
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
		// Reverse big-endian → little-endian to recover original byte layout.
		for i, j := 0, fieldBytes-1; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		out = append(out, b[:bytesPerField]...)
	}

	return bytes.TrimRight(out, "\x00"), nil
}

// ParsedInputs is the unified, human-readable view of both ZK circuit outputs.
// It is safe to serialise directly to JSON in API responses.
type ParsedInputs struct {
	Challenge        string   `json:"challenge"`
	PkCommit         string   `json:"pk_commit"`
	SubjectDNHash    string   `json:"subject_dn_hash"`
	IssuerRSAModulus []string `json:"issuer_rsa_modulus"`
	SmtRoot          string   `json:"smt_root"`
	SerialNumber     string   `json:"serial_number"`
}

// ParsePublicInputsRS2048 parses raw PublicSignals from an RS2048 link-verify
// run into a single ParsedInputs value.
func ParsePublicInputsRS2048(certChain, deviceSig []string) (*ParsedInputs, error) {
	cc, err := ParseCertChainRS2048(certChain)
	if err != nil {
		return nil, fmt.Errorf("cert_chain: %w", err)
	}
	ds, err := ParseDeviceSig(deviceSig)
	if err != nil {
		return nil, fmt.Errorf("device_sig: %w", err)
	}
	challenge, err := ds.Challenge()
	if err != nil {
		return nil, fmt.Errorf("challenge: %w", err)
	}
	return &ParsedInputs{
		Challenge:        challenge,
		PkCommit:         cc.PkCommit,
		SubjectDNHash:    cc.SubjectDNHash,
		IssuerRSAModulus: cc.IssuerRSAModulus,
		SmtRoot:          cc.SmtRoot,
		SerialNumber:     cc.SerialNumber,
	}, nil
}

// ParsePublicInputsRS4096 parses raw PublicSignals from an RS4096 link-verify
// run into a single ParsedInputs value.
func ParsePublicInputsRS4096(certChain, deviceSig []string) (*ParsedInputs, error) {
	cc, err := ParseCertChainRS4096(certChain)
	if err != nil {
		return nil, fmt.Errorf("cert_chain: %w", err)
	}
	ds, err := ParseDeviceSig(deviceSig)
	if err != nil {
		return nil, fmt.Errorf("device_sig: %w", err)
	}
	challenge, err := ds.Challenge()
	if err != nil {
		return nil, fmt.Errorf("challenge: %w", err)
	}
	return &ParsedInputs{
		Challenge:        challenge,
		PkCommit:         cc.PkCommit,
		SubjectDNHash:    cc.SubjectDNHash,
		IssuerRSAModulus: cc.IssuerRSAModulus,
		SmtRoot:          cc.SmtRoot,
		SerialNumber:     cc.SerialNumber,
	}, nil
}
