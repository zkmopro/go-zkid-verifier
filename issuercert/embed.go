package issuercert

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"fmt"
	"time"
)

//go:embed certs/moica-g2.cer
var embeddedMoicaG2 []byte

//go:embed certs/moica-g3.cer
var embeddedMoicaG3 []byte

//go:embed certs/grca-g2.cer
var embeddedGrcaG2 []byte

//go:embed certs/grca-g3.cer
var embeddedGrcaG3 []byte

// Pinned SHA-256 fingerprints for embedded certs.
var (
	// c4c462de463f856804dc898338d2cecb55fba74155851599d8fb7d70218fd1be
	pinnedMoicaG2SHA256 = [32]byte{
		0xc4, 0xc4, 0x62, 0xde, 0x46, 0x3f, 0x85, 0x68, 0x04, 0xdc, 0x89, 0x83, 0x38, 0xd2, 0xce, 0xcb,
		0x55, 0xfb, 0xa7, 0x41, 0x55, 0x85, 0x15, 0x99, 0xd8, 0xfb, 0x7d, 0x70, 0x21, 0x8f, 0xd1, 0xbe,
	}
	// ed793fd0d50a2a398049d598982cf01e75f873b532066caec238f800a06ca9da
	pinnedMoicaG3SHA256 = [32]byte{
		0xed, 0x79, 0x3f, 0xd0, 0xd5, 0x0a, 0x2a, 0x39, 0x80, 0x49, 0xd5, 0x98, 0x98, 0x2c, 0xf0, 0x1e,
		0x75, 0xf8, 0x73, 0xb5, 0x32, 0x06, 0x6c, 0xae, 0xc2, 0x38, 0xf8, 0x00, 0xa0, 0x6c, 0xa9, 0xda,
	}
	// 70b922bfda0e3f4a342e4ee22d579ae598d071cc5ec9c30f123680340388aea5
	pinnedGrcaG2SHA256 = [32]byte{
		0x70, 0xb9, 0x22, 0xbf, 0xda, 0x0e, 0x3f, 0x4a, 0x34, 0x2e, 0x4e, 0xe2, 0x2d, 0x57, 0x9a, 0xe5,
		0x98, 0xd0, 0x71, 0xcc, 0x5e, 0xc9, 0xc3, 0x0f, 0x12, 0x36, 0x80, 0x34, 0x03, 0x88, 0xae, 0xa5,
	}
	// 57df6f20e04c588e85f35be8832f5d4e78958336ae3b18fb7c9bae0dfead4044
	pinnedGrcaG3SHA256 = [32]byte{
		0x57, 0xdf, 0x6f, 0x20, 0xe0, 0x4c, 0x58, 0x8e, 0x85, 0xf3, 0x5b, 0xe8, 0x83, 0x2f, 0x5d, 0x4e,
		0x78, 0x95, 0x83, 0x36, 0xae, 0x3b, 0x18, 0xfb, 0x7c, 0x9b, 0xae, 0x0d, 0xfe, 0xad, 0x40, 0x44,
	}
)

// LoadEmbedded parses and validates embedded MOICA and GRCA certs.
func LoadEmbedded(now time.Time) (map[IssuerID]*CertRecord, error) {
	grcaG2, err := parseRoot(embeddedGrcaG2, pinnedGrcaG2SHA256, "GRCA-G2")
	if err != nil {
		return nil, err
	}
	grcaG3, err := parseRoot(embeddedGrcaG3, pinnedGrcaG3SHA256, "GRCA-G3")
	if err != nil {
		return nil, err
	}
	g2, err := parseAndValidate(embeddedMoicaG2, pinnedMoicaG2SHA256, grcaG2, IssuerG2, SourceEmbedded, now)
	if err != nil {
		return nil, fmt.Errorf("load embedded MOICA-G2: %w", err)
	}
	g3, err := parseAndValidate(embeddedMoicaG3, pinnedMoicaG3SHA256, grcaG3, IssuerG3, SourceEmbedded, now)
	if err != nil {
		return nil, fmt.Errorf("load embedded MOICA-G3: %w", err)
	}
	return map[IssuerID]*CertRecord{IssuerG2: g2, IssuerG3: g3}, nil
}

// GRCARootFor returns the embedded GRCA parent for an issuer.
func GRCARootFor(id IssuerID) (*x509.Certificate, error) {
	switch id {
	case IssuerG2:
		return parseRoot(embeddedGrcaG2, pinnedGrcaG2SHA256, "GRCA-G2")
	case IssuerG3:
		return parseRoot(embeddedGrcaG3, pinnedGrcaG3SHA256, "GRCA-G3")
	}
	return nil, fmt.Errorf("no GRCA parent known for issuer %d", id)
}

func parseRoot(der []byte, expected [32]byte, name string) (*x509.Certificate, error) {
	if sha256.Sum256(der) != expected {
		return nil, fmt.Errorf("embedded %s fingerprint drift — rebuild required", name)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse embedded %s: %w", name, err)
	}
	return cert, nil
}
