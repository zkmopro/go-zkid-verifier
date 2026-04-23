package issuercert

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/zkmopro/go-zkid-verifier/smtroot"
)

type IssuerID = smtroot.IssuerID

const (
	IssuerG2 = smtroot.IssuerG2
	IssuerG3 = smtroot.IssuerG3

	SourceEmbedded = "embedded"
	SourceHTTPS    = "https"
)

// CertRecord is a trusted MOICA CA cert snapshot.
type CertRecord struct {
	Parsed    *x509.Certificate
	PubKey    *rsa.PublicKey
	SHA256    [32]byte
	SHA256Hex string
	Limbs     []string
	Source    string
	FetchedAt time.Time
}

func LimbCountFor(id IssuerID) int {
	if id == IssuerG3 {
		return LimbsRS4096
	}
	return LimbsRS2048
}

type Config struct {
	Sources         map[IssuerID]Source
	RefreshInterval time.Duration
	FetchTimeout    time.Duration
	Logger          smtroot.Logger
}

// AttemptStat mirrors smtroot.AttemptStat.
type AttemptStat = smtroot.AttemptStat

type CertStatus struct {
	Issuer      string    `json:"issuer"`
	SHA256      string    `json:"sha256"`
	Subject     string    `json:"subject"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Source      string    `json:"source"`
	FetchedAt   time.Time `json:"fetched_at"`
	ModulusBits int       `json:"modulus_bits"`
}

type Status struct {
	Certs           map[string]CertStatus  `json:"certs"`
	UpdatedAt       time.Time              `json:"updated_at"`
	LastAttemptAt   time.Time              `json:"last_attempt_at"`
	LastError       string                 `json:"last_error,omitempty"`
	ConsecutiveFail int                    `json:"consecutive_fail"`
	CacheAgeSeconds int64                  `json:"cache_age_seconds"`
	Attempts        map[string]AttemptStat `json:"attempts"`
}

type Meta struct {
	UpdatedAt       time.Time
	CacheAgeSeconds int64
}

type Provider struct {
	sources map[IssuerID]Source
	refresh time.Duration
	timeout time.Duration
	log     smtroot.Logger
	now     func() time.Time

	mu              sync.RWMutex
	certs           map[IssuerID]*CertRecord
	updatedAt       time.Time
	lastAttemptAt   time.Time
	lastError       string
	consecutiveFail int
	attempts        map[string]*AttemptStat

	stopOnce sync.Once
	stopCh   chan struct{}
}

func NewProvider(cfg Config) (*Provider, error) {
	if cfg.Logger == nil {
		cfg.Logger = smtroot.DefaultLogger{}
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 24 * time.Hour
	}
	if cfg.FetchTimeout <= 0 {
		cfg.FetchTimeout = 10 * time.Second
	}
	p := &Provider{
		sources:  cfg.Sources,
		refresh:  cfg.RefreshInterval,
		timeout:  cfg.FetchTimeout,
		log:      cfg.Logger,
		now:      time.Now,
		certs:    map[IssuerID]*CertRecord{},
		attempts: map[string]*AttemptStat{},
		stopCh:   make(chan struct{}),
	}
	records, err := LoadEmbedded(p.now())
	if err != nil {
		return nil, fmt.Errorf("load embedded certs: %w", err)
	}
	p.certs = records
	p.updatedAt = p.now()
	return p, nil
}

// NewStaticProvider serves fixed records without refresh.
func NewStaticProvider(records map[IssuerID]*CertRecord) *Provider {
	p := &Provider{
		now:      time.Now,
		certs:    records,
		attempts: map[string]*AttemptStat{},
		stopCh:   make(chan struct{}),
		log:      smtroot.DefaultLogger{},
	}
	p.updatedAt = p.now()
	return p
}

func (p *Provider) Trusted(issuer IssuerID) (*CertRecord, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	rec, ok := p.certs[issuer]
	return rec, ok
}

// TrustedWithMeta returns the cert and cache metadata under one read lock.
func (p *Provider) TrustedWithMeta(issuer IssuerID) (*CertRecord, Meta, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	rec, ok := p.certs[issuer]
	m := Meta{UpdatedAt: p.updatedAt}
	if !p.updatedAt.IsZero() {
		m.CacheAgeSeconds = int64(p.now().Sub(p.updatedAt).Seconds())
	}
	return rec, m, ok
}

func (p *Provider) Meta() Meta {
	p.mu.RLock()
	defer p.mu.RUnlock()
	m := Meta{UpdatedAt: p.updatedAt}
	if !p.updatedAt.IsZero() {
		m.CacheAgeSeconds = int64(p.now().Sub(p.updatedAt).Seconds())
	}
	return m
}

func (p *Provider) Status() Status {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := Status{
		Certs:           make(map[string]CertStatus, len(p.certs)),
		UpdatedAt:       p.updatedAt,
		LastAttemptAt:   p.lastAttemptAt,
		LastError:       p.lastError,
		ConsecutiveFail: p.consecutiveFail,
		Attempts:        make(map[string]AttemptStat, len(p.attempts)),
	}
	for id, rec := range p.certs {
		out.Certs[id.ShortName()] = CertStatus{
			Issuer:      id.LongName(),
			SHA256:      rec.SHA256Hex,
			Subject:     rec.Parsed.Subject.String(),
			NotBefore:   rec.Parsed.NotBefore,
			NotAfter:    rec.Parsed.NotAfter,
			Source:      rec.Source,
			FetchedAt:   rec.FetchedAt,
			ModulusBits: rec.PubKey.N.BitLen(),
		}
	}
	for name, stat := range p.attempts {
		out.Attempts[name] = *stat
	}
	if !p.updatedAt.IsZero() {
		out.CacheAgeSeconds = int64(p.now().Sub(p.updatedAt).Seconds())
	}
	return out
}

func (p *Provider) setCert(id IssuerID, rec *CertRecord) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.certs[id] = rec
	p.updatedAt = p.now()
}

func (p *Provider) recordAttempt(source string, latency time.Duration, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastAttemptAt = p.now()
	stat, ok := p.attempts[source]
	if !ok {
		stat = &AttemptStat{}
		p.attempts[source] = stat
	}
	stat.Count++
	stat.LastLatencyMs = latency.Milliseconds()
	if err != nil {
		stat.LastErr = err.Error()
		p.lastError = err.Error()
		p.consecutiveFail++
		return
	}
	stat.LastErr = ""
	p.lastError = ""
	p.consecutiveFail = 0
}
