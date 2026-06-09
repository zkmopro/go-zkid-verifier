// Package smtroot fetches and caches trusted SMT revocation roots published by
// privacy-ethereum/moica-revocation-smt, so link-verify can reject proofs carrying a
// stale or forged smt_root public input.
package smtroot

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type IssuerID int

const (
	IssuerG2 IssuerID = iota
	IssuerG3
)

var AllIssuers = []IssuerID{IssuerG2, IssuerG3}

// LongName MUST match the keccak256 pre-image the SMTRootStorage contract
// indexes roots by.
func (i IssuerID) LongName() string {
	switch i {
	case IssuerG2:
		return "MOICA-G2"
	case IssuerG3:
		return "MOICA-G3"
	default:
		return fmt.Sprintf("IssuerID(%d)", i)
	}
}

// ShortName is the form used in the GitHub release body and JSON responses.
func (i IssuerID) ShortName() string {
	switch i {
	case IssuerG2:
		return "g2"
	case IssuerG3:
		return "g3"
	default:
		return "unknown"
	}
}

// Root is a 32-byte big-endian SMT root.
type Root [32]byte

// ParseRoot accepts any 0-padded hex up to 64 chars, with or without "0x".
func ParseRoot(s string) (Root, error) {
	var r Root
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return r, errors.New("empty root")
	}
	if len(s) > 64 {
		return r, fmt.Errorf("root longer than 32 bytes (%d hex chars)", len(s))
	}
	if len(s)%2 != 0 {
		s = "0" + s
	}
	if len(s) < 64 {
		s = strings.Repeat("0", 64-len(s)) + s
	}
	b, err := hex.DecodeString(strings.ToLower(s))
	if err != nil {
		return r, fmt.Errorf("decode hex: %w", err)
	}
	copy(r[:], b)
	return r, nil
}

func (r Root) Hex() string {
	return "0x" + hex.EncodeToString(r[:])
}

func (r Root) Equal(other Root) bool {
	return r == other
}

// IsZero — the SMTRootStorage contract returns zero for an unknown issuer,
// meaningfully distinct from "root is loaded".
func (r Root) IsZero() bool {
	return r == Root{}
}

type Source interface {
	FetchAll(ctx context.Context) (map[IssuerID]Root, error)
	Name() string
}

type AttemptStat struct {
	Count         int64  `json:"count"`
	LastLatencyMs int64  `json:"last_latency_ms"`
	LastErr       string `json:"last_err,omitempty"`
}

// Status is the payload served by /smt-root/status.
type Status struct {
	SourceUsed      string                 `json:"source_used"`
	Roots           map[string]string      `json:"roots"`
	UpdatedAt       time.Time              `json:"updated_at"`
	LastAttemptAt   time.Time              `json:"last_attempt_at"`
	LastError       string                 `json:"last_error,omitempty"`
	ConsecutiveFail int                    `json:"consecutive_fail"`
	CacheAgeSeconds int64                  `json:"cache_age_seconds"`
	Attempts        map[string]AttemptStat `json:"attempts"`
}

type Config struct {
	Primary         Source
	Fallback        Source        // optional
	RefreshInterval time.Duration // default 10m
	FetchTimeout    time.Duration // default 5s
	Logger          Logger        // default DefaultLogger
}

type Provider struct {
	primary  Source
	fallback Source
	refresh  time.Duration
	timeout  time.Duration
	log      Logger

	mu              sync.RWMutex
	roots           map[IssuerID]Root
	sourceUsed      string
	updatedAt       time.Time
	lastAttemptAt   time.Time
	lastError       string
	consecutiveFail int
	attempts        map[string]*AttemptStat

	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewProvider does not fetch; call FetchNow before serving traffic and Start
// to begin background refresh.
func NewProvider(cfg Config) *Provider {
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 10 * time.Minute
	}
	if cfg.FetchTimeout <= 0 {
		cfg.FetchTimeout = 5 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = DefaultLogger{}
	}
	return &Provider{
		primary:  cfg.Primary,
		fallback: cfg.Fallback,
		refresh:  cfg.RefreshInterval,
		timeout:  cfg.FetchTimeout,
		log:      cfg.Logger,
		roots:    map[IssuerID]Root{},
		attempts: map[string]*AttemptStat{},
		stopCh:   make(chan struct{}),
	}
}

// NewStaticProvider serves fixed roots with no refresh — for tests and local
// dev where fixtures reference a historical root.
func NewStaticProvider(roots map[IssuerID]Root) *Provider {
	p := NewProvider(Config{})
	p.setRoots(roots, "static", nil)
	return p
}

// Trusted returns false when no root has been loaded yet for the issuer.
func (p *Provider) Trusted(issuer IssuerID) (Root, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	r, ok := p.roots[issuer]
	return r, ok
}

// Meta is the allocation-free subset of Status for the per-request hot path.
type Meta struct {
	SourceUsed      string
	UpdatedAt       time.Time
	CacheAgeSeconds int64
}

func (p *Provider) Meta() Meta {
	p.mu.RLock()
	defer p.mu.RUnlock()
	m := Meta{SourceUsed: p.sourceUsed, UpdatedAt: p.updatedAt}
	if !p.updatedAt.IsZero() {
		m.CacheAgeSeconds = int64(time.Since(p.updatedAt).Seconds())
	}
	return m
}

func (p *Provider) Status() Status {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := Status{
		SourceUsed:      p.sourceUsed,
		Roots:           make(map[string]string, len(p.roots)),
		UpdatedAt:       p.updatedAt,
		LastAttemptAt:   p.lastAttemptAt,
		LastError:       p.lastError,
		ConsecutiveFail: p.consecutiveFail,
		Attempts:        make(map[string]AttemptStat, len(p.attempts)),
	}
	for issuer, root := range p.roots {
		out.Roots[issuer.ShortName()] = root.Hex()
	}
	for name, stat := range p.attempts {
		out.Attempts[name] = *stat
	}
	if !p.updatedAt.IsZero() {
		out.CacheAgeSeconds = int64(time.Since(p.updatedAt).Seconds())
	}
	return out
}

// setRoots installs roots on success or records the failure; on failure the
// previous cache is left in place (stale-on-error).
func (p *Provider) setRoots(roots map[IssuerID]Root, source string, err error) (changed map[IssuerID]bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	changed = make(map[IssuerID]bool, len(roots))
	now := time.Now()
	p.lastAttemptAt = now
	if err != nil {
		p.lastError = err.Error()
		p.consecutiveFail++
		return changed
	}
	for issuer, root := range roots {
		if old, ok := p.roots[issuer]; !ok || !old.Equal(root) {
			changed[issuer] = true
		}
		p.roots[issuer] = root
	}
	p.sourceUsed = source
	p.updatedAt = now
	p.lastError = ""
	p.consecutiveFail = 0
	return changed
}

func (p *Provider) recordAttempt(source string, latency time.Duration, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	stat, ok := p.attempts[source]
	if !ok {
		stat = &AttemptStat{}
		p.attempts[source] = stat
	}
	stat.Count++
	stat.LastLatencyMs = latency.Milliseconds()
	if err != nil {
		stat.LastErr = err.Error()
	} else {
		stat.LastErr = ""
	}
}
