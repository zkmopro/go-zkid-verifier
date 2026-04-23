package issuercert

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrNoSources = errors.New("issuercert: provider has no sources configured")

// FetchNow refreshes all configured issuers concurrently.
func (p *Provider) FetchNow(ctx context.Context, trigger string) error {
	if len(p.sources) == 0 {
		return ErrNoSources
	}
	p.log.Event("info", "issuer_cert_fetch_start", "trigger", trigger)

	var wg sync.WaitGroup
	errCh := make(chan error, len(p.sources))
	for id, src := range p.sources {
		wg.Add(1)
		go func(id IssuerID, src Source) {
			defer wg.Done()
			if err := p.fetchOne(ctx, trigger, id, src); err != nil {
				errCh <- fmt.Errorf("%s: %w", src.Name(), err)
			}
		}(id, src)
	}
	wg.Wait()
	close(errCh)

	var errs []error
	for e := range errCh {
		errs = append(errs, e)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (p *Provider) fetchOne(ctx context.Context, trigger string, id IssuerID, src Source) error {
	attemptCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	t0 := p.now()
	der, err := src.Fetch(attemptCtx)
	latency := p.now().Sub(t0)
	if err != nil {
		p.recordAttempt(src.Name(), latency, err)
		p.log.Event("warn", "issuer_cert_fetch_attempt",
			"trigger", trigger, "source", src.Name(),
			"ok", false, "latency_ms", latency.Milliseconds(),
			"err", err.Error())
		return err
	}

	var expected [32]byte
	switch id {
	case IssuerG2:
		expected = pinnedMoicaG2SHA256
	case IssuerG3:
		expected = pinnedMoicaG3SHA256
	default:
		err := fmt.Errorf("no pinned fingerprint for issuer %d", id)
		p.recordAttempt(src.Name(), latency, err)
		return err
	}

	parent, err := GRCARootFor(id)
	if err != nil {
		p.recordAttempt(src.Name(), latency, err)
		return err
	}
	rec, err := parseAndValidate(der, expected, parent, id, SourceHTTPS, p.now())
	if err != nil {
		p.recordAttempt(src.Name(), latency, err)
		p.log.Event("error", "issuer_cert_validation_failed",
			"trigger", trigger, "source", src.Name(),
			"issuer", id.LongName(), "err", err.Error())
		return err
	}

	p.setCert(id, rec)
	p.recordAttempt(src.Name(), latency, nil)
	p.log.Event("info", "issuer_cert_refreshed",
		"trigger", trigger, "source", src.Name(),
		"issuer", id.LongName(), "sha256", "0x"+hex.EncodeToString(rec.SHA256[:]),
		"not_after", rec.Parsed.NotAfter.Format(time.RFC3339),
		"latency_ms", latency.Milliseconds())
	return nil
}

// Start launches the background refresher.
func (p *Provider) Start(ctx context.Context) {
	if p.refresh <= 0 {
		return
	}
	go p.loop(ctx)
}

// Stop stops the background refresher.
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
