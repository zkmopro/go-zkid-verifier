package issuercert

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	DefaultG2URL = "https://moica.nat.gov.tw/repository/Certs/MOICA2.cer"
	DefaultG3URL = "https://moica.nat.gov.tw/repository/Certs/MOICA-G3.cer"

	maxCertBodyBytes = 64 * 1024
)

// Source fetches the raw DER bytes of one MOICA CA cert.
type Source interface {
	Issuer() IssuerID
	Name() string
	Fetch(ctx context.Context) ([]byte, error)
}

func NewHTTPSource(issuer IssuerID, url string, timeout time.Duration) Source {
	return &httpSource{
		issuer: issuer,
		url:    url,
		client: &http.Client{Timeout: timeout},
	}
}

func DefaultSources(g2URL, g3URL string, timeout time.Duration) map[IssuerID]Source {
	if g2URL == "" {
		g2URL = DefaultG2URL
	}
	if g3URL == "" {
		g3URL = DefaultG3URL
	}
	return map[IssuerID]Source{
		IssuerG2: NewHTTPSource(IssuerG2, g2URL, timeout),
		IssuerG3: NewHTTPSource(IssuerG3, g3URL, timeout),
	}
}

type httpSource struct {
	issuer IssuerID
	url    string
	client *http.Client
}

func (s *httpSource) Issuer() IssuerID { return s.issuer }
func (s *httpSource) Name() string     { return s.issuer.LongName() + "@" + s.url }

func (s *httpSource) Fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Accept", "application/pkix-cert, application/octet-stream, */*")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", s.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", s.url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCertBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(body) > maxCertBodyBytes {
		return nil, fmt.Errorf("body exceeds %d bytes", maxCertBodyBytes)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("empty body")
	}
	return body, nil
}
