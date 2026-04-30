package verifier

import (
	"encoding/hex"
	"fmt"
	"math/big"
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

// device_sig layout: [pk_commit, nullifier, app_id_packed, challenge].
// `app_id_packed` is the 31 leading bytes of `tbs` packed little-endian into one
// field element (matches the circuit's `tbs[0..31]` recovery). `challenge` is
// the verifier-issued per-session field element bound by a Semaphore-style
// dummy square.
type DeviceSigPublicInputs struct {
	PkCommit     string
	Nullifier    string
	AppIDPacked  string
	Challenge    string
}

const ExpectedDeviceSigSignals = 4

func ParseDeviceSig(signals []string) (*DeviceSigPublicInputs, error) {
	if len(signals) != ExpectedDeviceSigSignals {
		return nil, fmt.Errorf("device_sig requires exactly %d public inputs, got %d", ExpectedDeviceSigSignals, len(signals))
	}
	return &DeviceSigPublicInputs{
		PkCommit:    signals[0],
		Nullifier:   signals[1],
		AppIDPacked: signals[2],
		Challenge:   signals[3],
	}, nil
}

// PackAppIDLE encodes 31 bytes as a little-endian field-element decimal
// string, matching the circuit's `tbs[i] * 256^i` packing. NOTE: the
// per-session `challenge` value uses big-endian (see store.CreateChallenge);
// these two encodings are deliberately different.
func PackAppIDLE(b []byte) (string, error) {
	if len(b) != AppIDLen {
		return "", fmt.Errorf("app_id must be %d bytes, got %d", AppIDLen, len(b))
	}
	rev := make([]byte, AppIDLen)
	for i := 0; i < AppIDLen; i++ {
		rev[i] = b[AppIDLen-1-i]
	}
	return new(big.Int).SetBytes(rev).String(), nil
}

// UnpackAppIDHex turns a packed decimal field element back into a 62-char
// lowercase hex string of the original 31 bytes (little-endian interpretation).
func UnpackAppIDHex(packed string) (string, error) {
	s := strings.TrimSpace(packed)
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
		base = 16
	}
	n, ok := new(big.Int).SetString(s, base)
	if !ok {
		return "", fmt.Errorf("parse packed app_id %q", packed)
	}
	if n.Sign() < 0 {
		return "", fmt.Errorf("packed app_id is negative")
	}
	raw := n.Bytes() // big-endian; leading zeros stripped
	if len(raw) > AppIDLen {
		return "", fmt.Errorf("packed app_id exceeds %d bytes", AppIDLen)
	}
	// Reverse big-endian raw into low-index positions of out so out[i] holds
	// byte i of the original message (little-endian, zero-padded on the high
	// end up to 31 bytes).
	out := make([]byte, AppIDLen)
	for i := 0; i < len(raw); i++ {
		out[i] = raw[len(raw)-1-i]
	}
	return hex.EncodeToString(out), nil
}

type ParsedInputs struct {
	PkCommit         string   `json:"pk_commit"`
	Nullifier        string   `json:"nullifier"`
	AppID            string   `json:"app_id"`
	AppIDPacked      string   `json:"app_id_packed"`
	Challenge        string   `json:"challenge"`
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
	appID, err := UnpackAppIDHex(ds.AppIDPacked)
	if err != nil {
		return nil, fmt.Errorf("device_sig: %w", err)
	}
	return &ParsedInputs{
		PkCommit:         cc.PkCommit,
		Nullifier:        ds.Nullifier,
		AppID:            appID,
		AppIDPacked:      ds.AppIDPacked,
		Challenge:        ds.Challenge,
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
	appID, err := UnpackAppIDHex(ds.AppIDPacked)
	if err != nil {
		return nil, fmt.Errorf("device_sig: %w", err)
	}
	return &ParsedInputs{
		PkCommit:         cc.PkCommit,
		Nullifier:        ds.Nullifier,
		AppID:            appID,
		AppIDPacked:      ds.AppIDPacked,
		Challenge:        ds.Challenge,
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
