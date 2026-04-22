package smtroot

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrNoSource = errors.New("smtroot: provider has no source configured")

// FetchNow tries primary then fallback. On any success the cache is updated
// and the provider is healthy; on total failure the previous cache (if any)
// is retained and the joined error is returned.
func (p *Provider) FetchNow(ctx context.Context, trigger string) error {
	if p.primary == nil && p.fallback == nil {
		return ErrNoSource
	}

	p.log.Event("info", "smt_root_fetch_start", "trigger", trigger)

	sources := make([]Source, 0, 2)
	if p.primary != nil {
		sources = append(sources, p.primary)
	}
	if p.fallback != nil {
		sources = append(sources, p.fallback)
	}

	start := time.Now()
	var errs []error
	for _, src := range sources {
		attemptCtx, cancel := context.WithTimeout(ctx, p.timeout)
		t0 := time.Now()
		roots, err := src.FetchAll(attemptCtx)
		cancel()
		latency := time.Since(t0)
		p.recordAttempt(src.Name(), latency, err)

		if err != nil {
			p.log.Event("warn", "smt_root_fetch_attempt",
				"trigger", trigger,
				"source", src.Name(),
				"ok", false,
				"latency_ms", latency.Milliseconds(),
				"err", err.Error())
			errs = append(errs, fmt.Errorf("%s: %w", src.Name(), err))
			continue
		}
		p.log.Event("info", "smt_root_fetch_attempt",
			"trigger", trigger,
			"source", src.Name(),
			"ok", true,
			"latency_ms", latency.Milliseconds())

		changed := p.setRoots(roots, src.Name(), nil)
		p.logRefreshed(trigger, src.Name(), roots, changed, time.Since(start))
		return nil
	}

	joined := errors.Join(errs...)
	p.setRoots(nil, "", joined)
	status := p.Status()
	p.log.Event("error", "smt_root_fetch_failed",
		"trigger", trigger,
		"consecutive_fail", status.ConsecutiveFail,
		"last_err", joined.Error(),
		"cache_age_seconds", status.CacheAgeSeconds)
	return joined
}

func (p *Provider) logRefreshed(trigger, source string, roots map[IssuerID]Root, changed map[IssuerID]bool, total time.Duration) {
	kv := []any{
		"trigger", trigger,
		"source", source,
		"total_latency_ms", total.Milliseconds(),
	}
	for _, issuer := range AllIssuers {
		kv = append(kv, issuer.ShortName(), roots[issuer].Hex())
		kv = append(kv, issuer.ShortName()+"_changed", changed[issuer])
	}
	p.log.Event("info", "smt_root_refreshed", kv...)
}

// Start launches the background refresher. Stop or ctx cancellation tears it down.
func (p *Provider) Start(ctx context.Context) {
	if p.refresh <= 0 {
		return
	}
	go p.loop(ctx)
}

// Stop is safe to call multiple times.
func (p *Provider) Stop() {
	p.stopOnce.Do(func() { close(p.stopCh) })
}

func (p *Provider) loop(ctx context.Context) {
	t := time.NewTicker(p.refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		case <-t.C:
			_ = p.FetchNow(ctx, "scheduled")
		}
	}
}
