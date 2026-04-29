package verifier

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

const AppIDLen = 31

// cert_chain RS2048 layout: [pk_commit, issuer_modulus[17], smt_root].
type CertChainRS2048PublicInputs struct {
	PkCommit         string
	IssuerRSAModulus []string
	SmtRoot          string
}

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

// cert_chain RS4096 layout: [pk_commit, issuer_modulus[34], smt_root].
type CertChainRS4096PublicInputs struct {
	PkCommit         string
	IssuerRSAModulus []string
	SmtRoot          string
}

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

// device_sig layout: [pk_commit, nullifier, app_id_bytes[31]].
type DeviceSigPublicInputs struct {
	PkCommit  string
	Nullifier string
	AppIDHex  string
}

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

// Reject out-of-byte-range elements: a malformed proof must not be able to
// smuggle field-sized data through the byte-by-byte binding check.
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

type ParsedInputs struct {
	PkCommit         string   `json:"pk_commit"`
	Nullifier        string   `json:"nullifier"`
	AppID            string   `json:"app_id"`
	IssuerRSAModulus []string `json:"issuer_rsa_modulus"`
	SmtRoot          string   `json:"smt_root"`
}

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
