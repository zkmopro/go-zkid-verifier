package verifier

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// AppIDLen is the per-challenge app_id length, in bytes. Mirrors store.AppIDLen
// to avoid the verifier package depending on store.
const AppIDLen = 31

// CertChainRS2048PublicInputs holds the named public values from the cert_chain
// RS2048 circuit.
//
// Layout (19 field elements):
//
//	0:     pk_commit
//	1–17:  issuer_rsa_modulus  (17 limbs)
//	18:    smt_root
type CertChainRS2048PublicInputs struct {
	PkCommit         string
	IssuerRSAModulus []string // 17 limbs
	SmtRoot          string
}

// ParseCertChainRS2048 parses the raw CertChain signal slice from PublicSignals
// into named fields.
func ParseCertChainRS2048(signals []string) (*CertChainRS2048PublicInputs, error) {
	const required = 19
	if len(signals) != required {
		return nil, fmt.Errorf("cert_chain RS2048 requires exactly %d public inputs, got %d", required, len(signals))
	}
	return &CertChainRS2048PublicInputs{
		PkCommit:         signals[0],
		IssuerRSAModulus: signals[1:18],
		SmtRoot:          signals[18],
	}, nil
}

// CertChainRS4096PublicInputs holds the named public values from the cert_chain
// RS4096 circuit.
//
// Layout (36 field elements):
//
//	0:     pk_commit
//	1–34:  issuer_rsa_modulus  (34 limbs)
//	35:    smt_root
type CertChainRS4096PublicInputs struct {
	PkCommit         string
	IssuerRSAModulus []string // 34 limbs
	SmtRoot          string
}

// ParseCertChainRS4096 parses the raw CertChain signal slice from PublicSignals
// into named fields.
func ParseCertChainRS4096(signals []string) (*CertChainRS4096PublicInputs, error) {
	const required = 36
	if len(signals) != required {
		return nil, fmt.Errorf("cert_chain RS4096 requires exactly %d public inputs, got %d", required, len(signals))
	}
	return &CertChainRS4096PublicInputs{
		PkCommit:         signals[0],
		IssuerRSAModulus: signals[1:35],
		SmtRoot:          signals[35],
	}, nil
}

// DeviceSigPublicInputs holds the named public values from the device_sig
// circuit.
//
// Layout (33 field elements):
//
//	0:        pk_commit
//	1:        nullifier  = ChunkedPoseidonP256(rsa_signature_limbs)
//	2..32:    app_id_bytes (one byte per element, value < 256)
type DeviceSigPublicInputs struct {
	PkCommit  string
	Nullifier string
	AppIDHex  string // 62-char lowercase hex of app_id_bytes[0..31]
}

// ParseDeviceSig parses the raw DeviceSig signal slice into named fields.
func ParseDeviceSig(signals []string) (*DeviceSigPublicInputs, error) {
	const required = 2 + AppIDLen
	if len(signals) != required {
		return nil, fmt.Errorf("device_sig requires exactly %d public inputs, got %d", required, len(signals))
	}
	appID, err := decodeAppIDBytes(signals[2 : 2+AppIDLen])
	if err != nil {
		return nil, fmt.Errorf("decode app_id_bytes: %w", err)
	}
	return &DeviceSigPublicInputs{
		PkCommit:  signals[0],
		Nullifier: signals[1],
		AppIDHex:  appID,
	}, nil
}

// decodeAppIDBytes turns 31 small field elements (each < 256) into a 62-char
// lowercase hex string. Values outside [0, 255] error out so a malformed
// proof cannot smuggle field-sized data through the binding check.
func decodeAppIDBytes(elements []string) (string, error) {
	out := make([]byte, len(elements))
	for i, raw := range elements {
		s := strings.TrimSpace(raw)
		base := 10
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			s = s[2:]
			base = 16
		}
		n, err := strconv.ParseUint(s, base, 16)
		if err != nil {
			return "", fmt.Errorf("element %d: parse %q: %w", i, raw, err)
		}
		if n > 255 {
			return "", fmt.Errorf("element %d: value %d out of byte range", i, n)
		}
		out[i] = byte(n)
	}
	return hex.EncodeToString(out), nil
}

// ParsedInputs is the unified, human-readable view of both ZK circuit outputs.
// It is safe to serialise directly to JSON in API responses.
type ParsedInputs struct {
	PkCommit         string   `json:"pk_commit"`
	Nullifier        string   `json:"nullifier"`
	AppID            string   `json:"app_id"`
	IssuerRSAModulus []string `json:"issuer_rsa_modulus"`
	SmtRoot          string   `json:"smt_root"`
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
	return &ParsedInputs{
		PkCommit:         cc.PkCommit,
		Nullifier:        ds.Nullifier,
		AppID:            ds.AppIDHex,
		IssuerRSAModulus: cc.IssuerRSAModulus,
		SmtRoot:          cc.SmtRoot,
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
	return &ParsedInputs{
		PkCommit:         cc.PkCommit,
		Nullifier:        ds.Nullifier,
		AppID:            ds.AppIDHex,
		IssuerRSAModulus: cc.IssuerRSAModulus,
		SmtRoot:          cc.SmtRoot,
	}, nil
}

// ParsePublicInputs dispatches to the variant parser. Prefer this over the
// per-variant functions when t is not statically known.
func ParsePublicInputs(signals *PublicSignals, t CertChainType) (*ParsedInputs, error) {
	if signals == nil {
		return nil, fmt.Errorf("nil public signals")
	}
	switch t {
	case CertChainRS4096:
		return ParsePublicInputsRS4096(signals.CertChain, signals.DeviceSig)
	default:
		return ParsePublicInputsRS2048(signals.CertChain, signals.DeviceSig)
	}
}
