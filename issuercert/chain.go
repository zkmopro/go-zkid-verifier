package issuercert

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"
)

func parseAndValidate(der []byte, expectedSHA256 [32]byte, parent *x509.Certificate, id IssuerID, source string, now time.Time) (*CertRecord, error) {
	gotSHA := sha256.Sum256(der)
	if gotSHA != expectedSHA256 {
		return nil, fmt.Errorf("sha256 fingerprint mismatch: got %x, want %x", gotSHA, expectedSHA256)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse x509: %w", err)
	}
	if err := validateChain(cert, parent, now); err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want *rsa.PublicKey", cert.PublicKey)
	}
	k := LimbCountFor(id)
	expectedBits := 2048
	if id == IssuerG3 {
		expectedBits = 4096
	}
	if pub.N.BitLen() != expectedBits {
		return nil, fmt.Errorf("%s modulus is %d bits, want %d", id.LongName(), pub.N.BitLen(), expectedBits)
	}
	return &CertRecord{
		Parsed:    cert,
		PubKey:    pub,
		SHA256:    gotSHA,
		SHA256Hex: "0x" + hex.EncodeToString(gotSHA[:]),
		Limbs:     ModulusToLimbs(pub.N, k),
		Source:    source,
		FetchedAt: now,
	}, nil
}

func validateChain(intermediate, root *x509.Certificate, now time.Time) error {
	if err := intermediate.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("signature from parent: %w", err)
	}
	if !bytes.Equal(intermediate.RawIssuer, root.RawSubject) {
		return fmt.Errorf("issuer DN %q does not match parent subject DN %q", intermediate.Issuer, root.Subject)
	}
	if !root.IsCA {
		return fmt.Errorf("parent %q is not a CA", root.Subject)
	}
	if root.KeyUsage != 0 && root.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("parent %q KeyUsage=%d lacks CertSign", root.Subject, root.KeyUsage)
	}
	if now.Before(intermediate.NotBefore) {
		return fmt.Errorf("intermediate not yet valid (notBefore=%s)", intermediate.NotBefore)
	}
	if now.After(intermediate.NotAfter) {
		return fmt.Errorf("intermediate expired (notAfter=%s)", intermediate.NotAfter)
	}
	return nil
}
